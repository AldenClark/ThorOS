// SPDX-License-Identifier: GPL-2.0-or-later
/* Native PON downstream map; GPL aal_pdc.c and software CPU forwarding. */
#include <linux/bitfield.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include "rtl9617c-pon.h"
#include "rtl9617c-pon-data.h"

#define PDC_COUNTER 0x9000
#define PDC_CTRL 0x9014
#define PDC_ACCESS 0x9020
#define PDC_DATA1 0x9024
#define PDC_DATA0 0x9028

static int rtl_pdc_access(struct rtl9617c_pon *pon, unsigned int index, bool write)
{
	u32 status;
	if (readl(pon->mac + PDC_ACCESS) & BIT(31))
		return -EBUSY;
	writel(BIT(31) | (write ? BIT(30) : 0) | index, pon->mac + PDC_ACCESS);
	return readl_poll_timeout(pon->mac + PDC_ACCESS, status, !(status & BIT(31)), 1, 100000);
}

/* A timed-out request can still own DATA0/1. Do not corrupt its staging
 * window on a later control retry; the PON state lock excludes new owners. */
static int rtl_pdc_write(struct rtl9617c_pon *pon, unsigned int index,
			u32 data0, u32 data1)
{
	if (readl(pon->mac + PDC_ACCESS) & BIT(31))
		return -EBUSY;
	writel(data0, pon->mac + PDC_DATA0);
	writel(data1, pon->mac + PDC_DATA1);
	return rtl_pdc_access(pon, index, true);
}

int rtl_pon_pdc_refresh(struct rtl9617c_pon *pon)
{
	unsigned int index, bank;
	int ret;

	lockdep_assert_held(&pon->lock);
	if (!pon->pdc_configured || !rtl_pon_mode_is_epon(pon->mode))
		return 0;
	for (index = 0; index < 64; index++) {
		u32 source = rtl_pon_data_source(index, readl(pon->mac + 0x64 + index * 4));

		if (pon->pdc_source[index] == source)
			continue;
		for (bank = 0; bank < 2; bank++) {
			ret = rtl_pdc_write(pon, index | (bank << 7),
				(pon->fe_enabled ? 24 : 16) << 3 | (7 << 9) |
				(pon->fe_enabled ? 0 : BIT(15)), (source - 32) << 4);
			if (ret) {
				pon->pdc_error = ret;
				pon->pdc_configured = false;
				return ret;
			}
		}
		pon->pdc_source[index] = source;
	}
	return 0;
}

static int rtl_pdc_itu_configure(struct rtl9617c_pon *pon)
{
	unsigned int index;
	int ret;

	/* ITU slots0..7 are OMCC; all remaining selectors are internal GEM indices. */
	for (index = 0; index < 256; index++) {
		u32 word = (16 << 3) | (7 << 9) | BIT(15);
		u32 pol_id = index < 8 ? index + 128 : index - 8;

		if (index < 8)
			word |= BIT(31) | 6;
		else
			word = (24 << 3) | (7 << 9);
		ret = rtl_pdc_write(pon, index, word, pol_id << 4);
		if (ret)
			return ret;
	}
	rtl_pon_update(pon->mac + PDC_CTRL, GENMASK(25, 16) | GENMASK(2, 0),
		BIT(1) | (7 << 16) | (16 << 19) | BIT(25));
	rtl_pon_update(pon->mac + PDC_COUNTER, GENMASK(2, 0), 0);
	return 0;
}

int rtl_pon_pdc_configure_locked(struct rtl9617c_pon *pon)
{
	unsigned int index;
	int ret = 0;

	lockdep_assert_held(&pon->control_lock);
	mutex_lock(&pon->lock);
	if (!pon->mac_prepared) {
		ret = -EAGAIN;
		goto unlock;
	}
	pon->pdc_configured = false;
	if (!rtl_pon_mode_is_epon(pon->mode)) {
		/* Prepare the original-packet CPU miss before admitting ITU data.
		 * OMCI retains its dedicated CPU16 header container. */
		if (!pon->fe_enabled) {
			ret = rtl9617c_ni_fe_cpu_path(pon->ni_dev);
			if (ret)
				goto unlock;
			pon->fe_cpu_path = true;
		}
		ret = rtl_pdc_itu_configure(pon);
		pon->pdc_configured = !ret;
		goto unlock;
	}
	/* CRC stays on the wire only; PDC inserts its original 16-byte control header. */
	rtl_pon_update(pon->mac + PDC_CTRL, GENMASK(2, 0) | GENMASK(25, 16), 7);
	for (index = 0; index < 256; index++) {
		unsigned int entry = index & 63;
		unsigned int source = index & BIT(6) ? 7 :
			rtl_pon_data_source(entry, readl(pon->mac + 0x64 + entry * 4));
		u32 data0 = (16 << 3) | (7 << 9) | BIT(15);

		if (index & BIT(6))
			data0 |= 7;
		else
			pon->pdc_source[entry] = source;
		/* Keep the physical PON source; POL_ID carries the LLID without
		 * enabling either hardware policer. Upper CPU source IDs are
		 * normalized by the NI receive fabric on this board. */
		ret = rtl_pdc_write(pon, index, data0,
			index & BIT(6) ? 0 : (source - 32) << 4);
		if (ret)
			goto unlock;
	}
	rtl_pon_update(pon->mac + PDC_COUNTER, GENMASK(2, 0), 0);
	pon->pdc_configured = true;
	dev_info(pon->dev, "PDC: 256 downstream map entries configured for native CPU16\n");
unlock:
	pon->pdc_error = ret;
	mutex_unlock(&pon->lock);
	return ret;
}

static int rtl_pon_fe_set_locked(struct rtl9617c_pon *pon,bool enable,bool cpu_path)
{
 unsigned int entry,bank;
 int ret=0;

 lockdep_assert_held(&pon->control_lock);
 mutex_lock(&pon->lock);
 if(enable && (!pon->pdc_configured || !pon->puc_configured ||
               (rtl_pon_mode_is_epon(pon->mode) && !pon->traffic_enabled))) {
  ret=-EAGAIN;
  goto unlock;
 }
 /* FE ownership is committed before the per-entry PDC update. This is a
  * staged, retryable transition, not an atomic rollback: retain both the
  * actual FE mode and configured map on failure so stop/retry can finish. */
 if(enable) {
  ret=rtl9617c_ni_fe_enable(pon->ni_dev);
  if(ret)goto unlock;
  pon->fe_enabled=true;
  pon->fe_cpu_path=false;
 } else if(cpu_path) {
  ret=rtl9617c_ni_fe_cpu_path(pon->ni_dev);
  if(ret)goto unlock;
  pon->fe_enabled=false;
  pon->fe_cpu_path=true;
 }
 /* OAM/control maps retain CPU16 and their original header container. */
 if(pon->pdc_configured && rtl_pon_mode_is_epon(pon->mode))
  for(entry=0;entry<64;entry++)
   for(bank=0;bank<2;bank++) {
    ret=rtl_pdc_write(pon,entry|(bank<<7),
     ((enable?24:16)<<3)|(7<<9)|(enable?0:BIT(15)),(pon->pdc_source[entry]-32)<<4);
    if(ret)goto unlock;
   }
 if(pon->pdc_configured && !rtl_pon_mode_is_epon(pon->mode))
  for(entry=8;entry<256;entry++) {
   u32 data;
   /* ITU selectors0..7 retain OMCI CPU containers; data follows the GEM map. */
   ret=rtl_pdc_access(pon,entry,false);
   if(ret)goto unlock;
   data=readl(pon->mac+PDC_DATA0);
   ret=rtl_pdc_write(pon,entry,
    (data&~((63U<<3)|BIT(15)))|(((enable||cpu_path)?24:16)<<3)|
    ((enable||cpu_path)?0:BIT(15)),readl(pon->mac+PDC_DATA1));
   if(ret)goto unlock;
  }
 if(!enable && !cpu_path) {
  ret=rtl9617c_ni_fe_disable(pon->ni_dev);
  if(ret)goto unlock;
  pon->fe_cpu_path=false;
 }
 pon->fe_enabled=enable;
unlock:
 /* Preserve the original configuration fault when admission is not ready.
  * A no-map stop must not erase it either. Only a complete mapped transition
  * establishes a clean PDC state; never clear pdc_configured on this path. */
 if(ret) {
  if(ret!=-EAGAIN || !pon->pdc_error)pon->pdc_error=ret;
 } else if(pon->pdc_configured)pon->pdc_error=0;
 mutex_unlock(&pon->lock);
 return ret;
}

int rtl_pon_fe_configure_locked(struct rtl9617c_pon *pon,bool enable)
{
 return rtl_pon_fe_set_locked(pon,enable,!enable && !rtl_pon_mode_is_epon(pon->mode));
}

int rtl_pon_fe_stop_locked(struct rtl9617c_pon *pon)
{
 return rtl_pon_fe_set_locked(pon,false,false);
}

ssize_t rtl_pon_pdc_state(struct rtl9617c_pon *pon, char *buf)
{
	static const unsigned int sample[] = {0, 8, 9, 10, 31, 63, 64, 127, 192, 255};
	ssize_t length;
	unsigned int i;
	int ret;

	length = sysfs_emit(buf, "configured=%u error=%d control=%08x counter_cfg=%08x\n",
		pon->pdc_configured, pon->pdc_error, readl(pon->mac + PDC_CTRL), readl(pon->mac + PDC_COUNTER));
	for (i = 0; i < ARRAY_SIZE(sample); i++) {
		ret = rtl_pdc_access(pon, sample[i], false);
		if (ret)
			return ret;
		length += scnprintf(buf + length, PAGE_SIZE - length,
			"index=%u data=%08x/%08x destination=%u source=%u bypass=%u cos=%u pol_id=%u\n",
			sample[i], readl(pon->mac + PDC_DATA0), readl(pon->mac + PDC_DATA1),
			(unsigned int)FIELD_GET(GENMASK(8, 3), readl(pon->mac + PDC_DATA0)),
			(unsigned int)FIELD_GET(GENMASK(14, 9), readl(pon->mac + PDC_DATA0)),
			!!(readl(pon->mac + PDC_DATA0) & BIT(15)), readl(pon->mac + PDC_DATA0) & 7, (readl(pon->mac + PDC_DATA1) >> 4) & 511);
	}
	return length;
}
