// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2025, Advanced Micro Devices, Inc.
 */
#include <linux/device.h>
#include <linux/version.h>
#include <linux/completion.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/fdtable.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/mmap_lock.h>

#include "amdxdna_ctx.h"
#include "ve2_of.h"
#include "ve2_mgmt.h"
#include "ve2_res_solver.h"
#include "amdxdna_error.h"

/* Module parameter: delay in seconds before waking threads on AIE error (for devmem debug) */
static int aie_error_delay_sec;
module_param(aie_error_delay_sec, int, 0644);
MODULE_PARM_DESC(aie_error_delay_sec, "Delay in seconds on AIE error before waking threads (for devmem debug, default=0)");

static struct amdxdna_mgmtctx *ve2_create_mgmt_partition(struct amdxdna_dev *xdna,
				     struct xrs_action_load *load_act);

static void cert_setup_partition(struct amdxdna_dev *xdna,
				 struct amdxdna_ctx_priv *nhwctx,
				 u32 col, struct handshake *cert_hs)
{
	struct ve2_config_hwctx *hwctx_cfg = &nhwctx->hwctx_config[col];
	u64 hsa_addr = 0xFFFFFFFFFFFFFFFF;
	u32 start_col = nhwctx->start_col;
	u32 num_col = nhwctx->num_col;
	u32 lead_col_addr;
	u64 host_time_ns;

	/* Store current host time */
	host_time_ns = ktime_get_ns();
	cert_hs->host_time_low  = (u32)(host_time_ns & 0xFFFFFFFF);
	cert_hs->host_time_high = (u32)(host_time_ns >> 32);

	if (col == 0)
		hsa_addr = nhwctx->hwctx_hsa_queue.hsa_queue_mem.dma_addr;

	lead_col_addr = VE2_ADDR(start_col, 0, 0);

	cert_hs->partition_base_address = lead_col_addr;
	cert_hs->aie_info.partition_size = num_col;
	cert_hs->hsa_addr_high =  upper_32_bits(hsa_addr);
	cert_hs->hsa_addr_low =  lower_32_bits(hsa_addr);
	cert_hs->log_addr_high = upper_32_bits(hwctx_cfg->log_buf_addr);
	cert_hs->log_addr_low = lower_32_bits(hwctx_cfg->log_buf_addr);
	cert_hs->log_buf_size = hwctx_cfg->log_buf_size;
	cert_hs->dbg_buf.dbg_buf_addr_high = upper_32_bits(hwctx_cfg->debug_buf_addr);
	cert_hs->dbg_buf.dbg_buf_addr_low = lower_32_bits(hwctx_cfg->debug_buf_addr);
	cert_hs->dbg_buf.size = hwctx_cfg->debug_buf_size;

	/* Dtrace Buffer */
	cert_hs->trace.dtrace_addr_high = upper_32_bits(hwctx_cfg->dtrace_addr);
	cert_hs->trace.dtrace_addr_low = lower_32_bits(hwctx_cfg->dtrace_addr);

	/* Opcode Timeout */
	cert_hs->opcode_timeout_config = hwctx_cfg->opcode_timeout_config;

	cert_hs->ctx_switch_req = 0;
	cert_hs->hsa_location = 0;
	cert_hs->dbg.hsa_addr_high = 0xFFFFFFFF;
	cert_hs->dbg.hsa_addr_low = 0xFFFFFFFF;
	cert_hs->mpaie_alive = ALIVE_MAGIC;
}

static void ve2_free_hs_data(struct aie_op_handshake_data *hs_data, u32 max_cols)
{
	if (!hs_data)
		return;

	for (u32 col = 0; col < max_cols; col++) {
		kfree(hs_data[col].addr);
		hs_data[col].addr = NULL;
	}
	kfree(hs_data);
	hs_data = NULL;
}

static struct aie_op_handshake_data *ve2_prepare_hs_data(struct amdxdna_dev *xdna,
							 struct amdxdna_ctx_priv *nhwctx,
							 bool init)
{
	struct aie_op_handshake_data *hs_data;
	u32 num_col = nhwctx->num_col;
	struct aie_location aie_loc;

	hs_data = kmalloc_array(num_col, sizeof(*hs_data), GFP_KERNEL);
	if (!hs_data) {
		XDNA_ERR(xdna, "No memory for handshake data allocation\n");
		return NULL;
	}

	for (u32 col = 0; col < num_col; col++) {
		struct handshake *cert_hs;

		aie_loc.col = col;
		cert_hs = kmalloc(sizeof(*cert_hs), GFP_KERNEL);
		if (!cert_hs) {
			XDNA_ERR(xdna, "No memory for cert hs packet\n");
			/* Free previously allocated handshakes */
			ve2_free_hs_data(hs_data, col);
			return NULL;
		}
		memset(cert_hs, 0, sizeof(*cert_hs));
		if (init)
			cert_setup_partition(xdna, nhwctx, col, cert_hs);

		hs_data[col].addr = (void *)cert_hs;
		hs_data[col].size = sizeof(struct handshake);
		hs_data[col].offset = 0x0;
		hs_data[col].loc = aie_loc;
	}

	return hs_data;
}

int ve2_xrs_col_list(struct amdxdna_dev *xdna, struct alloc_requests *xrs_req,
		     u32 num_col)
{
	int total_col = xrs_get_total_cols(xdna->dev_handle->xrs_hdl);
	int i, start;
	int max_start = total_col - num_col;
	int entries = 0;

	if (start_col > 0) {
		if (start_col + num_col > total_col) {
			XDNA_ERR(xdna, "Invalid start_col_index %d, num col %d",
				 start_col, num_col);
			return -EINVAL;
		}

		for (start = start_col; start <= max_start; start += MIN_COL_SUPPORT)
			entries++;
	} else {
		for (start = 0; start <= max_start; start += MIN_COL_SUPPORT)
			entries++;
	}

	if (entries == 0) {
		XDNA_ERR(xdna, "No valid start_col found for num_col %d in total_col %d",
			 num_col, total_col);
		return -EINVAL;
	}

	xrs_req->cdo.start_cols = kmalloc_array(entries,
						sizeof(*xrs_req->cdo.start_cols),
						GFP_KERNEL);
	if (!xrs_req->cdo.start_cols) {
		XDNA_ERR(xdna, "Failed to allocate start_cols array (entries=%u)", entries);
		return -ENOMEM;
	}

	xrs_req->cdo.cols_len = entries;
	for (i = 0, start = (start_col > 0 ? start_col : 0); start <= max_start;
	     start += MIN_COL_SUPPORT, i++)
		xrs_req->cdo.start_cols[i] = start;

	print_hex_dump_debug("col_list: ", DUMP_PREFIX_OFFSET, 16, 4,
			     xrs_req->cdo.start_cols,
			     entries * sizeof(*xrs_req->cdo.start_cols), false);
	return 0;
}

/**
 * ve2_detach_hwctx_from_partition - Detach hwctx from partition and re-enqueue
 * @xdna: Device handle
 * @mgmtctx: Partition to detach from
 * @hwctx: Hardware context to detach
 *
 * Detaches hwctx from partition and puts it back in scheduler queue.
 * This is used for partition preemption (context switching).
 */
static void ve2_detach_hwctx_from_partition(struct amdxdna_dev *xdna,
					     struct amdxdna_mgmtctx *mgmtctx,
					     struct amdxdna_ctx *hwctx)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;

	XDNA_DBG(xdna, "detach: hwctx=%p from partition [%u,%u)",
		 hwctx, mgmtctx->start_col, mgmtctx->start_col + mgmtctx->ncol);

	/* Remove from partition's FIFO */
	ve2_fifo_remove_ctx(mgmtctx, hwctx);

	/* Clear active context if this is it */
	if (mgmtctx->active_ctx == hwctx) {
		mgmtctx->active_ctx = NULL;
		mgmtctx->is_partition_idle = 1;
	}

	/* Clear hwctx's partition assignment */
	nhwctx->mgmtctx = NULL;
	/*
	 * Also clear aie_dev: ve2_xrs_reclaim_partition()'s global scan only
	 * finds hwctxs where nhwctx->mgmtctx == the reclaimed mgmtctx.  Since
	 * we just cleared mgmtctx above, the scan would skip this hwctx and
	 * leave nhwctx->aie_dev pointing at the (about-to-be-freed) AIE
	 * partition device — a dangling pointer.  Clear it now so any code
	 * that checks aie_dev before mgmtctx is reassigned sees NULL.
	 */
	nhwctx->aie_dev = NULL;
	/* Note: Keep start_col/num_col so ve2_xrs_release can work */

	/* Re-enqueue to scheduler pending list for rescheduling */
	mutex_lock(&xdna_hdl->pending_lock);
	if (nhwctx->sched_entry.dying) {
		/*
		 * ve2_hwctx_fini() already marked this entry dying under
		 * pending_lock, meaning the hwctx is being destroyed.  Do NOT
		 * re-enqueue: doing so would put a ghost entry back into the
		 * scheduler list after fini has freed priv, causing the next
		 * scheduler pass to dereference NULL or freed memory.
		 */
		pr_warn("amdxdna: detach: hwctx=%p is dying, skipping re-enqueue "
			"(submitted=%llu completed=%llu)\n",
			hwctx, hwctx->submitted, hwctx->completed);
	} else if (!nhwctx->sched_entry.in_list) {
		printk("HIMANSHU detach_reenqueue: hwctx=%p re-enqueued to pending list\n", hwctx);
		list_add_tail(&nhwctx->sched_entry.list, &xdna_hdl->pending_hwctx_list);
		nhwctx->sched_entry.in_list = true;
	}
	mutex_unlock(&xdna_hdl->pending_lock);
}

/**
 * ve2_try_reclaim_for_allocation - Try to free space for a new partition allocation
 * @xdna: Device handle
 * @start_col: Start column of requested range
 * @ncols: Number of columns in requested range
 * @allow_preemption: If true, allows preempting active partitions
 *
 * Returns: 1 if space was freed, 0 if nothing could be reclaimed
 *
 * Strategy:
 * 1. Find all partitions overlapping [start_col, start_col+ncols)
 * 2. If any idle → reclaim all idle overlapping partitions
 * 3. If all busy and allow_preemption → pick best victim and preempt
 *
 * Best victim selection:
 * - Prefer exact size match (can reuse partition after preemption)
 * - Otherwise pick smallest overlapping (minimize wasted columns)
 */
static int ve2_try_reclaim_for_allocation(struct amdxdna_dev *xdna, u32 start_col, u32 ncols,
					   bool allow_preemption)
{
	struct amdxdna_dev_hdl *xdna_hdl = xdna->dev_handle;
	u32 end_col = start_col + ncols;
	u32 reclaimed = 0;
	u32 col;

	XDNA_DBG(xdna, "reclaim: searching [%u,%u) preempt=%d", start_col, end_col, allow_preemption);

	/*
	 * PASS 1: Cooperative idle reclaim.
	 *
	 * Reclaim every overlapping partition that the per-partition firmware
	 * scheduler has confirmed is idle (is_partition_idle == 1).  This
	 * flag is set by ve2_scheduler_work() when CERT signals no more work
	 * and no other context is waiting — meaning the firmware has finished
	 * the current command batch and it is safe to repurpose the columns.
	 *
	 * Crucially, this is a COOPERATIVE model:
	 *  - Partitions that are actively processing commands
	 *    (is_partition_idle == 0) are NEVER touched here.  Those hwctxs
	 *    continue uninterrupted on their own columns.
	 *  - Only partitions that have gone firmware-idle are reclaimed.
	 *  - The displaced hwctx is re-enqueued to the pending list so it
	 *    gets a fresh partition as soon as columns become available.
	 *
	 * For a large (e.g. 24-col) request competing with several small
	 * (e.g. 4-col) partitions: each small partition signals idle
	 * independently; every time one does, the device scheduler retries
	 * the allocation.  Once ALL overlapping partitions have gone idle
	 * (possibly at different times), PASS 1 reclaims them all and the
	 * retry succeeds.
	 */
	for (col = 0; col < xdna_hdl->aie_dev_info.cols; col++) {
		struct amdxdna_mgmtctx *mgmtctx = &xdna_hdl->ve2_mgmtctx[col];
		struct amdxdna_ctx_command_fifo *c_ctx, *t_ctx;
		u32 part_end;
		bool is_idle;

		if (!mgmtctx->mgmt_aiedev)
			continue;

		part_end = mgmtctx->start_col + mgmtctx->ncol;
		if (mgmtctx->start_col >= end_col || part_end <= start_col)
			continue;

		mutex_lock(&mgmtctx->ctx_lock);
		is_idle = mgmtctx->is_partition_idle;
		mutex_unlock(&mgmtctx->ctx_lock);

		if (!is_idle)
			continue;

		XDNA_DBG(xdna, "reclaim: firmware-idle partition [%u,%u)", mgmtctx->start_col, part_end);

		/*
		 * Detach any owner before destroying the partition.
		 * is_partition_idle==1 implies the FIFO is empty and the
		 * firmware has no outstanding work, but active_ctx may still
		 * point at the last hwctx that used this partition.  Detaching
		 * it here puts it back in the pending list so the device
		 * scheduler can reassign it a new (or the same) partition later.
		 */
		mutex_lock(&mgmtctx->ctx_lock);

		if (mgmtctx->active_ctx) {
			ve2_detach_hwctx_from_partition(xdna, mgmtctx,
							mgmtctx->active_ctx);
		}
		/* Safety: drain any stale FIFO entries (should be empty) */
		list_for_each_entry_safe(c_ctx, t_ctx,
					 &mgmtctx->ctx_command_fifo_head, list) {
			list_del(&c_ctx->list);
			ve2_detach_hwctx_from_partition(xdna, mgmtctx, c_ctx->ctx);
			kfree(c_ctx);
		}

		mutex_unlock(&mgmtctx->ctx_lock);

		if (ve2_xrs_reclaim_partition(xdna, mgmtctx->start_col,
					      mgmtctx->ncol) == 0)
			reclaimed++;
		else
			XDNA_ERR(xdna, "reclaim: failed to reclaim idle [%u,%u)",
				 mgmtctx->start_col, part_end);
	}

	XDNA_DBG(xdna, "reclaim: total %u firmware-idle partitions", reclaimed);
	return reclaimed;
}

int ve2_xrs_request(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
	struct solver_state *xrs = xdna->dev_handle->xrs_hdl;
        struct amdxdna_mgmtctx  *mgmtctx = NULL;
	struct xrs_action_load load_act = {0};
	struct amdxdna_ctx_priv *nhwctx = NULL;
	struct alloc_requests *xrs_req;
	int reclaim_attempts = 0;
	const int MAX_RECLAIM_ATTEMPTS = 1;
	int ret;

	if (!xrs)
		return -EINVAL;

	mutex_lock(&xrs->xrs_lock);
	xrs_req = kzalloc(sizeof(*xrs_req), GFP_KERNEL);
	if (!xrs_req) {
		XDNA_ERR(xdna, "Failed to allocate xrs request for hwctx_id=%u (pid=%u)",
			 hwctx->id, hwctx->client->pid);
		mutex_unlock(&xrs->xrs_lock);
		return -ENOMEM;
	}
    XDNA_DBG(xdna, "XRS request: ncols=%u (partition_size=%d, num_tiles=%u)",
		 xrs_req->cdo.ncols, partition_size, hwctx->num_tiles);
	if (partition_size < hwctx->num_tiles)
		xrs_req->cdo.ncols = hwctx->num_tiles;
	else
		xrs_req->cdo.ncols = partition_size;

	XDNA_DBG(xdna, "XRS request: ncols=%u (partition_size=%d, num_tiles=%u)",
		 xrs_req->cdo.ncols, partition_size, hwctx->num_tiles);

	ret = ve2_xrs_col_list(xdna, xrs_req, xrs_req->cdo.ncols);
	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS col resource failed, ret %d", ret);
		mutex_unlock(&xrs->xrs_lock);
		goto free_xrs_req;
	}

	xrs_req->rqos.priority = hwctx->qos.priority;

	/* Validate user_start_col if set */
	if (hwctx->qos.user_start_col != USER_START_COL_NOT_REQUESTED) {
		/* Check alignment: start_col must be a multiple of MIN_COL_SUPPORT (4) */
		if (hwctx->qos.user_start_col % MIN_COL_SUPPORT != 0) {
			XDNA_ERR(xdna, "user_start_col %u not aligned to %u",
				 hwctx->qos.user_start_col, MIN_COL_SUPPORT);
			mutex_unlock(&xrs->xrs_lock);
			ret = -EINVAL;
			goto free_start_cols;
		}

		/* Check bounds: start_col + ncols must not exceed total columns */
		if (hwctx->qos.user_start_col + xrs_req->cdo.ncols > xrs->cfg.total_col) {
			XDNA_ERR(xdna, "user_start_col %u + ncols %u exceeds total %u",
				 hwctx->qos.user_start_col, xrs_req->cdo.ncols, xrs->cfg.total_col);
			mutex_unlock(&xrs->xrs_lock);
			ret = -ERANGE;
			goto free_start_cols;
		}
	}
	xrs_req->rqos.user_start_col = hwctx->qos.user_start_col;
	xrs_req->rid = (uintptr_t)hwctx;

retry_allocation:
	ret = xrs_allocate_resource(xrs, xrs_req, &load_act);
	if (ret && reclaim_attempts < MAX_RECLAIM_ATTEMPTS) {
		/*
		 * XRS allocation failed — columns are occupied.  Try to reclaim
		 * any overlapping partitions that the firmware has confirmed are
		 * idle (is_partition_idle == 1).  Partitions with active
		 * firmware work are left untouched; the device scheduler will
		 * retry automatically when each of those partitions signals idle.
		 */
		int total_reclaimed = 0;

		XDNA_INFO(xdna, "[XRS-REQUEST] Allocation failed ret=%d, trying idle reclaim",
			  ret);

		mutex_unlock(&xrs->xrs_lock);

		for (int i = 0; i < xrs_req->cdo.cols_len; i++) {
			u32 candidate_col = xrs_req->cdo.start_cols[i];

			total_reclaimed += ve2_try_reclaim_for_allocation(xdna, candidate_col,
									  xrs_req->cdo.ncols,
									  false);
		}

		mutex_lock(&xrs->xrs_lock);
		reclaim_attempts++;

		if (total_reclaimed > 0) {
			XDNA_INFO(xdna, "[XRS-REQUEST] Reclaimed %d idle partitions, retrying",
				  total_reclaimed);
			goto retry_allocation;
		}

		/*
		 * No idle columns available yet.  The caller (device scheduler)
		 * will be re-triggered by ve2_scheduler_work() every time a
		 * partition goes firmware-idle, so this hwctx will be
		 * rescheduled automatically without busy-waiting.
		 */
		XDNA_DBG(xdna, "[XRS-REQUEST] No idle partitions available, will retry on next idle");
	}

	if (ret) {
		XDNA_ERR(xdna, "Allocate XRS resource failed after %d reclaim attempts, ret %d",
			 reclaim_attempts, ret);
		mutex_unlock(&xrs->xrs_lock);
		goto free_start_cols;
	}

	mgmtctx = ve2_create_mgmt_partition(xdna, &load_act);
	if (!mgmtctx) {
		XDNA_ERR(xdna, "Creating AIE partition failed, ret %d", ret);
		mutex_unlock(&xrs->xrs_lock);
		goto xrs_release;
	}

	nhwctx = hwctx->priv;
	if (!nhwctx) {
		/*
		 * ve2_hwctx_fini() already ran for this hwctx (set priv=NULL)
		 * but the stale pointer was still in the pending list.  Do not
		 * write through the NULL pointer.  The scheduler's entry-level
		 * NULL check in ve2_scheduler_work_handler is the primary guard;
		 * this is a belt-and-suspenders defence for races inside
		 * ve2_xrs_request() itself (e.g. after a PASS-1 reclaim retry).
		 */
		XDNA_ERR(xdna,
			 "ve2_xrs_request: hwctx=%p priv=NULL after partition assignment "
			 "– hwctx destroyed while scheduler held it (submitted=%llu completed=%llu)",
			 hwctx, hwctx->submitted, hwctx->completed);
		mutex_unlock(&xrs->xrs_lock);
		ret = -EINVAL;
		goto destroy_partition;
	}
	nhwctx->mgmtctx = mgmtctx;  /* Assign partition to hwctx */
        nhwctx->start_col = mgmtctx->start_col;
        nhwctx->num_col = mgmtctx->ncol;
	nhwctx->aie_dev = mgmtctx->mgmt_aiedev;
	nhwctx->args = &mgmtctx->args;
	/*
	 * Allocate hwctx_config array if not already done.
	 * Under lazy allocation, ve2_hwctx_init() pre-allocates this with
	 * num_tiles entries so CONFIG_HWCTX ioctls can arrive before the first
	 * command submission.  Only allocate here if it wasn't pre-allocated.
	 */
	if (!nhwctx->hwctx_config) {
		nhwctx->hwctx_config = kcalloc(nhwctx->num_col,
					       sizeof(*nhwctx->hwctx_config), GFP_KERNEL);
		if (!nhwctx->hwctx_config) {
			XDNA_ERR(xdna, "Failed to allocate hwctx_config");
			mutex_unlock(&xrs->xrs_lock);
			ret = -ENOMEM;
			goto destroy_partition;
		}
	}

        hwctx->start_col = nhwctx->start_col;
	hwctx->num_col = nhwctx->num_col;
	mutex_unlock(&xrs->xrs_lock);

	kfree(xrs_req->cdo.start_cols);
	kfree(xrs_req);
	return 0;

destroy_partition:
	ve2_mgmt_destroy_partition(mgmtctx);
xrs_release:
	xrs_release_resource(xrs, (uintptr_t)hwctx, &load_act);
	/* Clear priv XRS fields so ve2_hwctx_fini doesn't call ve2_xrs_release
	 * a second time on a solver_node that no longer exists.
	 */
	if (hwctx->priv) {
		hwctx->priv->start_col = 0;
		hwctx->priv->num_col = 0;
	}
free_start_cols:
	kfree(xrs_req->cdo.start_cols);
free_xrs_req:
	kfree(xrs_req);
	XDNA_ERR(xdna, "XRS Request Failed. Ret %d", ret);
	return ret;
}

// Function to display the queue
static void ve2_fifo_display_queue(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_ctx_command_fifo *c_ctx, *t_ctx;

	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list)
		XDNA_DBG(mgmtctx->xdna, "CTX : %p command index: %llu\n",
			 c_ctx->ctx, c_ctx->command_index);
}

// Enqueue a context into the FIFO queue
static int ve2_fifo_enqueue(struct amdxdna_mgmtctx *mgmtctx,
			    struct amdxdna_ctx *ctx, u64 command_index)
{
	struct amdxdna_ctx_command_fifo *node;

	node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->ctx = ctx;
	node->command_index = command_index;
	INIT_LIST_HEAD(&node->list);
	list_add_tail(&node->list, &mgmtctx->ctx_command_fifo_head);

	return 0;
}

/**
 * ve2_fifo_remove_ctx - Remove all FIFO entries for a given context
 * @mgmtctx: Pointer to the management context
 * @ctx: Pointer to the context to remove
 *
 * Must be called with mgmtctx->ctx_lock held.
 * This prevents use-after-free when a context is destroyed while
 * entries for it still exist in the scheduler FIFO.
 */
void ve2_fifo_remove_ctx(struct amdxdna_mgmtctx *mgmtctx, struct amdxdna_ctx *ctx)
{
	struct amdxdna_ctx_command_fifo *c_ctx, *t_ctx;

	lockdep_assert_held(&mgmtctx->ctx_lock);

	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list) {
		if (c_ctx->ctx == ctx) {
			XDNA_DBG(mgmtctx->xdna,
				 "Removing FIFO entry for ctx %p, cmd_index %llu\n",
				 ctx, c_ctx->command_index);
			list_del(&c_ctx->list);
			kfree(c_ctx);
		}
	}
}

// Get the context switch request bit
static u32 get_ctx_bit(struct amdxdna_mgmtctx *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 val;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, ctx_switch_req),
					  sizeof(u32), &val);
	return val;
}

void ve2_mgmt_handshake_init(struct amdxdna_dev *xdna,
			     struct amdxdna_ctx *hwctx)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;
	struct aie_op_handshake_data *hs_data;
	u32 start_col;
	u32 num_col;
	int ret = 0;

	start_col = nhwctx->start_col;
	num_col = nhwctx->num_col;

	hs_data = ve2_prepare_hs_data(xdna, nhwctx, true);
	if (!hs_data) {
		XDNA_ERR(xdna, "preparing cert handshake data failed ");
		return;
	}
	nhwctx->args->handshake_cols = num_col;
	nhwctx->args->handshake = (struct aie_op_handshake_data *)hs_data;
	nhwctx->args->init_opts = (AIE_PART_INIT_OPT_DEFAULT | AIE_PART_INIT_OPT_HANDSHAKE |
		AIE_PART_INIT_OPT_DIS_TLAST_ERROR) & ~AIE_PART_INIT_OPT_UC_ENB_MEM_PRIV;

	XDNA_DBG(xdna, "partition_init: start_col=%u num_col=%u hwctx=%p pid=%d",
		 start_col, num_col, hwctx, hwctx->client->pid);

	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_PARTITION_INIT",
				  hwctx->client->pid, start_col, hwctx->priv->id, num_col);
	ret = ve2_partition_initialize(nhwctx->aie_dev, nhwctx->args);
	if (ret < 0) {
		XDNA_ERR(xdna, "aie partition init failed: %d", ret);
		goto release_hs_data;
	}
	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_PARTITION_DONE",
				  hwctx->client->pid, start_col, hwctx->priv->id, num_col);

	for (int col = num_col - 1; col >= 0; col--)
		ve2_partition_uc_wakeup(nhwctx->aie_dev, col);

release_hs_data:
	ve2_free_hs_data(hs_data, num_col);
}

#define RR_SHARING BIT(0)
static int ve2_request_context_switch(struct amdxdna_dev *xdna,
				      struct amdxdna_mgmtctx *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 val, pval;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, ctx_switch_req),
					  sizeof(u32), &val);

	pval = val;
	val |= RR_SHARING;
	ve2_partition_write_privileged_mem(aie_dev, 0,
					   offsetof(struct handshake, ctx_switch_req),
					   sizeof(u32), (void *)&val);

	mgmtctx->is_context_req = 1;

	return 0;
}

static struct amdxdna_ctx *
ve2_response_ctx_switch_req(struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_dev *xdna = mgmtctx->xdna;
	struct amdxdna_ctx_command_fifo *c_ctx, *t_ctx;
	struct amdxdna_ctx *hwctx = NULL;

	/* Check if already locked */
	lockdep_assert_held(&mgmtctx->ctx_lock);
	XDNA_DBG(xdna, "printing fifo before context switch:\n");

	/* Debug Only */
	//ve2_fifo_displayQueue(mgmtctx);

	/* Top need to be scheduled */
	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list) {
		if (mgmtctx->is_idle_due_to_context == 1) {
			hwctx = c_ctx->ctx;
			mgmtctx->is_partition_idle = 0;
			/*
			 * Only re-initialize the partition when the context at
			 * the head of the FIFO is DIFFERENT from the one that
			 * was previously active.  If the same hwctx is coming
			 * back (e.g. it was the only one and the firmware went
			 * idle momentarily), skip the expensive handshake
			 * re-init — the firmware state is still valid.
			 */
			if (mgmtctx->active_ctx != hwctx) {
				XDNA_DBG(xdna, "ctx switch: %p -> %p, re-init",
					 mgmtctx->active_ctx, hwctx);
				ve2_mgmt_handshake_init(mgmtctx->xdna, hwctx);
				mgmtctx->active_ctx = hwctx;
			} else {
				XDNA_DBG(xdna, "ctx switch: same hwctx %p, skip re-init", hwctx);
			}
		}

		if (t_ctx && c_ctx->ctx != t_ctx->ctx)
			ve2_request_context_switch(mgmtctx->xdna, mgmtctx);

		break;
	}

	return hwctx;
}

int ve2_mgmt_schedule_cmd(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx,
			  u64 command_index)
{
	struct amdxdna_mgmtctx  *mgmtctx = hwctx->priv->mgmtctx;
	int ret;

	if (!mgmtctx) {
		XDNA_ERR(xdna, "hwctx %p is not assigned to any partition", hwctx);
		return -EINVAL;
	}

	XDNA_DBG(xdna,
		 "schedule_cmd: enter command_index=%llu start_col=%u hwctx=%p pid=%d",
		 (unsigned long long)command_index, mgmtctx->start_col, hwctx,
		 hwctx->client->pid);
	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_ENTER",
				  hwctx->client->pid, mgmtctx->start_col,
				  hwctx->priv->id, command_index);
	mutex_lock(&mgmtctx->ctx_lock);
	ret = ve2_fifo_enqueue(mgmtctx, hwctx, command_index);
	if (ret) {
		XDNA_DBG(xdna, "ve2_fifo_enqueue failed ret=%d cmd_idx=%llu hwctx=%p",
			 ret, (unsigned long long)command_index, hwctx);
		mutex_unlock(&mgmtctx->ctx_lock);
		return ret;
	}
	printk("HIMANSHU SCH ve2_fifo_enqueue ok cmd_idx=%llu hwctx=%p",
		 (unsigned long long)command_index, hwctx);

	if (!mgmtctx->active_ctx) {
		mgmtctx->is_partition_idle = 0;
		printk("HIMANSHU SCH SWITCH First command for partition, initializing hwctx %p", hwctx);
		/* First command request. Initiate the handshake */
		ve2_mgmt_handshake_init(xdna, hwctx);
		mgmtctx->active_ctx = hwctx;
	} else if (mgmtctx->active_ctx != hwctx) {
		if (mgmtctx->is_partition_idle == 1) {
			mgmtctx->is_partition_idle = 0;
			XDNA_DBG(xdna, "Context switch: active=%p -> new=%p (partition idle)",
				 mgmtctx->active_ctx, hwctx);
			printk("HIMANSHU SCH request Context switch: active=%p -> new=%p (partition idle)",
				 mgmtctx->active_ctx, hwctx);
			ve2_response_ctx_switch_req(mgmtctx);
		} else {
			XDNA_DBG(xdna, "Command queued: active=%p, pending=%p",
				 mgmtctx->active_ctx, hwctx);
			printk("HIMANSHU SCH Command queued: active=%p, pending=%p",
				 mgmtctx->active_ctx, hwctx);
		}
	} else {
		if (mgmtctx->is_idle_due_to_context == 1) {
			printk("HIMANSHU SCH SWITCH is_idle_due_to_context=1, initializing hwctx %p", hwctx);
			mgmtctx->is_idle_due_to_context = 0;
			mgmtctx->is_partition_idle = 0;
			ve2_mgmt_handshake_init(xdna, hwctx);
			mgmtctx->active_ctx = hwctx;
		} else {
			printk("HIMANSHU SCH already active hwctx %p", hwctx);
		}
	}

	mutex_unlock(&mgmtctx->ctx_lock);
	notify_fw_cmd_ready(mgmtctx->active_ctx);
	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_EXIT",
				  hwctx->client->pid, mgmtctx->start_col,
				  hwctx->priv->id, (int)command_index);
	printk(
		 "HIMANSHU schedule_cmd: exit command_index=%llu start_col=%u hwctx=%p pid=%d",
		 (unsigned long long)command_index, mgmtctx->start_col, hwctx,
		 hwctx->client->pid);

	return 0;
}

static bool ve2_check_context_req(struct amdxdna_mgmtctx  *mgmtctx)
{
	if (mgmtctx->is_context_req == 1) {
		mgmtctx->is_context_req = 0;
		mgmtctx->is_idle_due_to_context = 1;
		return true;
	}

	return false;
}

static bool ve2_check_idle(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;
	u32 val = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), (void *)&cert_idle_status);

	/* Make it always true for now */
	if (cert_idle_status & CERT_IS_IDLE) {
		XDNA_DBG(mgmtctx->xdna,
			 "%s: active hwctx %p cert_idle_status:%x cert_ctx_switch_bit:%x -->FOUND\n",
			 __func__, mgmtctx->active_ctx, cert_idle_status, val);
		return true;
	}
	XDNA_DBG(mgmtctx->xdna,
		 "%s: active hwctx %p cert_idle_status:%x cert_ctx_switch_bit:%x -->NOT Found\n",
		 __func__, mgmtctx->active_ctx, cert_idle_status, val);

	return false;
}

static bool ve2_check_queue_not_empty(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;
	u32 val = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), (void *)&cert_idle_status);

	/* Make it always true for now */
	if (cert_idle_status & HSA_QUEUE_NOT_EMPTY) {
		XDNA_DBG(mgmtctx->xdna,
			 "%s: active hwctx %p cert_idle_status:%x cert_ctx_switch_bit:%x -->FOUND\n",
			 __func__, mgmtctx->active_ctx, cert_idle_status, val);
		return true;
	}
	XDNA_DBG(mgmtctx->xdna,
		 "%s: active hwctx %p cert_idle_status:%x cert_ctx_switch_bit:%x -->Not Found\n",
		 __func__, mgmtctx->active_ctx, cert_idle_status, val);

	return false;
}

static bool ve2_check_misc_interrupt(struct amdxdna_mgmtctx *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 misc_status = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, misc_status),
					  sizeof(misc_status), (void *)&misc_status);
	/*This may occur when control code is hanged or any exception*/
	if (misc_status != 0) {
		if (mgmtctx->active_ctx && mgmtctx->active_ctx->priv)
			mgmtctx->active_ctx->priv->misc_intrpt_flag = true;
		else
			XDNA_ERR(mgmtctx->xdna,
				 "misc_status interrupt: active_ctx or priv is NULL");

		return true;
	}

	return false;
}

static bool ve2_check_idle_or_queue_not_empty(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status),
					  (void *)&cert_idle_status);

	/* Make it always true for now */
	if (cert_idle_status & HSA_QUEUE_NOT_EMPTY || cert_idle_status & CERT_IS_IDLE) {
		XDNA_DBG(mgmtctx->xdna,
			 "%s: active hwctx %p cert_idle_status:%x -> FOUND\n",
			 __func__, mgmtctx->active_ctx, cert_idle_status);
		return true;
	}
	XDNA_DBG(mgmtctx->xdna,
		 "%s: active hwctx %p cert_idle_status:%x -> Not Found\n",
		 __func__, mgmtctx->active_ctx, cert_idle_status);

	return false;
}

static void ve2_scheduler_work(struct work_struct *work)
{
	struct amdxdna_mgmtctx *mgmtctx =
		container_of(work, struct amdxdna_mgmtctx, sched_work);
	struct amdxdna_ctx *hwctx = NULL;

	mutex_lock(&mgmtctx->ctx_lock);
	hwctx = mgmtctx->active_ctx;
	if (!hwctx) {
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	/* Check if context is being destroyed */
	if (!mgmtctx->active_ctx || !mgmtctx->active_ctx->priv) {
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_ENTER",
				  hwctx->client->pid, mgmtctx->start_col, hwctx->priv->id,
				  0);

	XDNA_DBG(mgmtctx->xdna,
		 "scheduler: enter start_col=%u hwctx=%p pid=%d",
		 mgmtctx->start_col, mgmtctx->active_ctx,
		 mgmtctx->active_ctx->client->pid);

	/*
	 * 3 case possible:
	 * 1. it was completion interrupt but idle/queue_not_empty bit was set as cert moved forward
	 * 2. idle bit is set
	 * 3. queue_not_empty bit is set
	 */

	ve2_check_context_req(mgmtctx);

	if (mgmtctx->active_ctx->priv->misc_intrpt_flag) {
		XDNA_ERR(mgmtctx->xdna, "MISC interrupt from firmware!!!\n");
	} else if (ve2_check_queue_not_empty(mgmtctx)) {
		/*
		 * there are more command but cert ack ctx switch bit
		 * we schedule next ctx and if no more ctx are there we set partition idle
		 */
		if (!ve2_response_ctx_switch_req(mgmtctx)) {
			mgmtctx->is_partition_idle = 1;
			/*
			 * Unexpected: queue_not_empty was set but no more
			 * commands in FIFO.  Still signal idle to allow
			 * cooperative reclamation by pending large allocations.
			 */
			XDNA_DBG(mgmtctx->xdna,
				 "No more command in fifo and Partition is IDLE active hwctx:%p ------> ",
				 mgmtctx->active_ctx);
			queue_work(mgmtctx->xdna->dev_handle->sched_wq,
				   &mgmtctx->xdna->dev_handle->sched_work);
		}
	} else if (ve2_check_idle(mgmtctx)) {
		/*
		 * 1. no more command and cert is in idle
		 * 2. no more command and cert ack ctx switch bit
		 * in both condition we schedule next ctx and if no more ctx are there we set
		 * partition idle.
		 */
		if (!ve2_response_ctx_switch_req(mgmtctx)) {
			mgmtctx->is_partition_idle = 1;
			XDNA_DBG(mgmtctx->xdna, "Partition now idle, no pending contexts");
			/*
			 * Wake the device-level scheduler.  A larger partition
			 * request (e.g. 24-col) may be waiting in
			 * pending_hwctx_list and needs these columns.  Kicking
			 * the device scheduler here lets it retry the
			 * allocation cooperatively: each small partition signals
			 * idle independently, and once all columns the large
			 * request needs are idle the allocation succeeds.
			 */
			queue_work(mgmtctx->xdna->dev_handle->sched_wq,
				   &mgmtctx->xdna->dev_handle->sched_work);
		}
	} else {
		XDNA_DBG(mgmtctx->xdna, "Scheduler: no action needed, active_ctx=%p",
			 mgmtctx->active_ctx);
	}
	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_EXIT",
				  hwctx->client->pid,
				  hwctx->priv->start_col,
				  hwctx->priv->id, 0);

	XDNA_DBG(mgmtctx->xdna,
		 "scheduler: exit start_col=%u hwctx=%p pid=%d",
		 mgmtctx->start_col, hwctx,
		 hwctx->client->pid);
	mutex_unlock(&mgmtctx->ctx_lock);
}

static u32 get_cert_idle_status(struct amdxdna_mgmtctx  *mgmtctx)
{
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	u32 cert_idle_status = 0;

	ve2_partition_read_privileged_mem(aie_dev, 0,
					  offsetof(struct handshake, cert_idle_status),
					  sizeof(cert_idle_status), (void *)&cert_idle_status);

	return cert_idle_status;
}

static int pop_from_ctx_command_fifo_till(struct amdxdna_mgmtctx *mgmtctx,
					  struct amdxdna_ctx *active_ctx,
					  u64 read_index)
{
	struct amdxdna_ctx_command_fifo *c_ctx, *t_ctx;

	XDNA_DBG(mgmtctx->xdna, "%s for active_ctx:%p read_index:%llu\n",
		 __func__, active_ctx, read_index);
	XDNA_DBG(mgmtctx->xdna, "printing fifo before pop:\n");
	ve2_fifo_display_queue(mgmtctx);
	list_for_each_entry_safe(c_ctx, t_ctx, &mgmtctx->ctx_command_fifo_head, list) {
		if (c_ctx->ctx != active_ctx) {
			XDNA_DBG(mgmtctx->xdna,
				 "POP BREAK as next_ctx=%p != ctx:%p so setting ctx switch bit\n",
				 c_ctx->ctx, c_ctx);
			ve2_request_context_switch(mgmtctx->xdna, mgmtctx);
			break;
		}

		if (c_ctx->command_index <= read_index) {
			XDNA_DBG(mgmtctx->xdna, "POP ctx:%p command index:%llu\n",
				 c_ctx->ctx, c_ctx->command_index);
			list_del(&c_ctx->list);
			kfree(c_ctx);
		} else {
			XDNA_DBG(mgmtctx->xdna,
				 "POP BREAK at temp_ctx:%p command index:%llu active_ctx:%p read_index:%llu\n",
				 c_ctx->ctx, c_ctx->command_index, active_ctx, read_index);
			break;
		}
	}
	return 0;
}

static void ve2_irq_handler(u32 partition_id, void *cb_arg)
{
	struct amdxdna_mgmtctx  *mgmtctx = (struct amdxdna_mgmtctx *)cb_arg;
	u64 read_index = 0, write_index = 0;
	struct amdxdna_ctx *hwctx;
	struct amdxdna_dev *xdna;

	if (!mgmtctx)
		return;

	xdna = mgmtctx->xdna;
	XDNA_DBG(xdna, "IRQ received: partition_id=%u, start_col=%u",
		 partition_id, mgmtctx->start_col);
	mutex_lock(&mgmtctx->ctx_lock);

	/* Just wake active hwctx */
	hwctx = mgmtctx->active_ctx;
	if (!hwctx || !hwctx->priv) {
		XDNA_ERR(xdna, "Invalid hwctx");
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	XDNA_DBG(xdna,
		 "completion IRQ: enter start_col=%u hwctx=%p pid=%d",
		 mgmtctx->start_col, hwctx, hwctx->client->pid);

	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_ENTER",
				  hwctx->client->pid,
				  mgmtctx->start_col, hwctx->priv->id, 0);
	if (get_ctx_read_index(hwctx, &read_index)) {
		XDNA_ERR(xdna, "Failed to get read index for hwctx_id=%u (pid=%u)",
			 hwctx->id, hwctx->client->pid);
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	if (get_ctx_write_index(hwctx, &write_index)) {
		XDNA_ERR(xdna, "Failed to get write index for hwctx_id=%u (pid=%u)",
			 hwctx->id, hwctx->client->pid);
		mutex_unlock(&mgmtctx->ctx_lock);
		return;
	}

	XDNA_DBG(xdna, "IRQ: hwctx=%p, read_idx=%llu, write_idx=%llu, ctx_bit=%u, idle_status=0x%x",
		 hwctx, read_index, write_index, get_ctx_bit(mgmtctx),
		 get_cert_idle_status(mgmtctx));

	/* Race condition: what happen if more command completed bet this point and
	 * point waiq get executed(check for command completed). This will only happen
	 * when cert is not in sleep ... that means we got completion interrupt..
	 * if cert move forwarded to execute more command that is the expected behaviour..
	 * max to max we will go out of order.
	 */
	pop_from_ctx_command_fifo_till(mgmtctx, hwctx, read_index);

	wake_up_interruptible_all(&hwctx->priv->waitq);

	trace_amdxdna_trace_point("XRT_PROFILING_TRACE_EXIT",
				  hwctx->client->pid,
				  hwctx->priv->id, write_index,
				  read_index);

	mutex_unlock(&mgmtctx->ctx_lock);

	if (mgmtctx->mgmtctx_workq && (ve2_check_idle_or_queue_not_empty(mgmtctx) ||
				       ve2_check_misc_interrupt(mgmtctx))) {
		XDNA_DBG(xdna, "IRQ: queueing sched_work start_col=%u", mgmtctx->start_col);
		queue_work(mgmtctx->mgmtctx_workq, &mgmtctx->sched_work);
	} else {
		XDNA_DBG(xdna, "IRQ: sched_work not queued start_col=%u (wq=%p)",
			 mgmtctx->start_col, mgmtctx->mgmtctx_workq);
	}

	XDNA_DBG(xdna,
		 "completion IRQ: exit read_index=%llu write_index=%llu hwctx=%p pid=%d",
		 (unsigned long long)read_index, (unsigned long long)write_index,
		 hwctx, hwctx->client->pid);
}

/**
 * ve2_dump_debug_state - Dump HSA queue state and handshake data for debugging
 * @xdna: Pointer to the AMD XDNA device structure
 * @mgmtctx: Pointer to the management context
 *
 * This function dumps critical debug information when an AIE error occurs,
 * including HSA queue indices, completion states, and firmware handshake data.
 */
static void ve2_dump_debug_state(struct amdxdna_dev *xdna,
				 struct amdxdna_mgmtctx *mgmtctx)
{
	struct amdxdna_ctx *hwctx = mgmtctx->active_ctx;
	struct amdxdna_ctx_priv *priv;
	struct ve2_hsa_queue *hq;
	struct hsa_queue *queue;
	struct handshake *hs = NULL;
	int i;
	int ret;

	if (!hwctx || !hwctx->priv) {
		XDNA_WARN(xdna, "=== DEBUG DUMP: No active context ===\n");
		return;
	}

	priv = hwctx->priv;
	hq = &priv->hwctx_hsa_queue;
	queue = hq->hsa_queue_p;

	if (!queue) {
		XDNA_WARN(xdna, "=== DEBUG DUMP: No HSA queue allocated ===\n");
		return;
	}

	/* Use XDNA_WARN (non-ratelimited) so the full dump is visible. */
	XDNA_WARN(xdna, "=== VE2 DEBUG DUMP START (hwctx=%p) ===\n", hwctx);

	/* hq_lock protects read_index, write_index, reserved_write_index (ve2_host_queue.h) */
	mutex_lock(&hq->hq_lock);

	/* Sync read_index before reading (device writes this) */
	hsa_queue_sync_read_index_for_read(hq);
	/* Note: write_index is written by CPU, so no sync needed for reading */

	/* Dump HSA queue header */
	XDNA_WARN(xdna, "HSA Queue Header:\n");
	XDNA_WARN(xdna, "  read_index:     %llu\n", queue->hq_header.read_index);
	XDNA_WARN(xdna, "  write_index:    %llu\n", queue->hq_header.write_index);
	XDNA_WARN(xdna, "  reserved_write: %llu\n", hq->reserved_write_index);
	XDNA_WARN(xdna, "  capacity:       %u\n", queue->hq_header.capacity);
	XDNA_WARN(xdna, "  data_address:   0x%llx\n", queue->hq_header.data_address);
	XDNA_WARN(xdna, "  dma_addr:       0x%llx\n", hq->hsa_queue_mem.dma_addr);

	/* Calculate pending commands */
	XDNA_WARN(xdna, "  pending_cmds:   %llu\n",
		  queue->hq_header.write_index - queue->hq_header.read_index);

	/* Dump completion status for all slots */
	XDNA_WARN(xdna, "HSA Queue Completion Status:\n");
	for (i = 0; i < HOST_QUEUE_ENTRY; i++) {
		/* Sync completion memory before reading (device may have written) */
		hsa_queue_sync_completion_for_read(hq, i);
		u64 completion = hq->hq_complete.hqc_mem[i];

		if (completion != 0)
			XDNA_WARN(xdna, "  slot[%2d]: state=%llu\n", i, completion);
	}

	/* Dump packet info for pending slots */
	XDNA_WARN(xdna, "HSA Queue Packet Details:\n");
	for (i = 0; i < HOST_QUEUE_ENTRY; i++) {
		struct host_queue_packet *pkt = &queue->hq_entry[i];
		u64 completion = hq->hq_complete.hqc_mem[i];
		u64 expected_signal = hq->hq_complete.hqc_dma_addr + i * sizeof(u64);

		/* Show all non-invalid packets OR packets with unexpected state */
		if (pkt->xrt_header.common_header.type != HOST_QUEUE_PACKET_TYPE_INVALID ||
		    completion != 0) {
			XDNA_WARN(xdna,
				  "  slot[%2d]: type=%u opcode=%u count=%u chain=%u dist=%u indir=%u\n",
				  i,
				  pkt->xrt_header.common_header.type,
				  pkt->xrt_header.common_header.opcode,
				  pkt->xrt_header.common_header.count,
				  pkt->xrt_header.common_header.chain_flag,
				  pkt->xrt_header.common_header.distribute,
				  pkt->xrt_header.common_header.indirect);
			XDNA_WARN(xdna, "           signal=0x%llx (expected=0x%llx) state=%llu\n",
				  pkt->xrt_header.completion_signal, expected_signal, completion);
			/* Check for signal mismatch - indicates potential corruption */
			if (pkt->xrt_header.common_header.type != HOST_QUEUE_PACKET_TYPE_INVALID &&
			    pkt->xrt_header.completion_signal != expected_signal) {
				XDNA_WARN(xdna,
					  "  *** SIGNAL MISMATCH! Possible packet corruption ***\n");
			}
			/* Check for invalid opcode - potential corruption */
			if (pkt->xrt_header.common_header.type != HOST_QUEUE_PACKET_TYPE_INVALID &&
			    pkt->xrt_header.common_header.opcode != HOST_QUEUE_PACKET_EXEC_BUF) {
				XDNA_WARN(xdna,
					  "  *** INVALID OPCODE %u! Expected %u. Possible corruption ***\n",
					  pkt->xrt_header.common_header.opcode,
					  HOST_QUEUE_PACKET_EXEC_BUF);
			}
			/* Check for invalid count */
			if (pkt->xrt_header.common_header.type != HOST_QUEUE_PACKET_TYPE_INVALID &&
			    !pkt->xrt_header.common_header.indirect &&
			    pkt->xrt_header.common_header.count != sizeof(struct exec_buf)) {
				XDNA_WARN(xdna,
					  "  *** INVALID COUNT %u! Expected %zu. Possible corruption ***\n",
					  pkt->xrt_header.common_header.count,
					  sizeof(struct exec_buf));
			}

			/* Dump exec_buf data (instruction buffer addresses)
			 * for non-indirect packets
			 */
			if (!pkt->xrt_header.common_header.indirect) {
				struct exec_buf *ebp = (struct exec_buf *)pkt->data;
				u64 instr_addr = ((u64)ebp->dpu_control_code_host_addr_high << 32) |
						 ebp->dpu_control_code_host_addr_low;
				u64 dtrace_addr = ((u64)ebp->dtrace_buf_host_addr_high << 32) |
						  ebp->dtrace_buf_host_addr_low;

				XDNA_WARN(xdna,
					  "           instr_addr=0x%llx dtrace=0x%llx args_len=%u\n",
					  instr_addr, dtrace_addr, ebp->args_len);

				/* Flag potentially invalid addresses */
				if (!instr_addr)
					XDNA_WARN(xdna,
						  "  *** ZERO INSTRUCTION ADDR! Possible corruption ***\n");
			}
		}
	}

	mutex_unlock(&hq->hq_lock);

	/* Read and dump handshake data from firmware */
	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs) {
		XDNA_WARN(xdna, "No memory for handshake; skipping handshake/VM dump\n");
		return;
	}
	ret = ve2_partition_read_privileged_mem(priv->aie_dev, 0, 0, sizeof(*hs), hs);
	if (ret) {
		XDNA_WARN(xdna,
			  "Failed to read firmware handshake data (ret=%d); skipping handshake/VM dump\n",
			  ret);
		kfree(hs);
		return;
	}

	XDNA_WARN(xdna, "Firmware Handshake Data:\n");
	XDNA_WARN(xdna, "  mpaie_alive:        0x%x %s\n", hs->mpaie_alive,
		  (hs->mpaie_alive == ALIVE_MAGIC) ? "(ALIVE)" : "(NOT ALIVE!)");
	XDNA_WARN(xdna, "  partition_base:     0x%x\n", hs->partition_base_address);
	XDNA_WARN(xdna, "  partition_size:     %u cols\n", hs->aie_info.partition_size);
	XDNA_WARN(xdna, "  hsa_addr:           0x%x%08x\n", hs->hsa_addr_high, hs->hsa_addr_low);
	XDNA_WARN(xdna, "  ctx_switch_req:     0x%x\n", hs->ctx_switch_req);
	XDNA_WARN(xdna, "  cert_idle_status:   0x%x\n", hs->cert_idle_status);
	XDNA_WARN(xdna, "  misc_status:        0x%x\n", hs->misc_status);
	XDNA_WARN(xdna, "  runlist_read_idx:   0x%x\n", hs->runlist_read_idx);
	XDNA_WARN(xdna, "  doorbell_pending:   %u\n", hs->doorbell_pending);

	/* Dump VM state (firmware execution context) */
	XDNA_WARN(xdna, "Firmware VM State:\n");
	XDNA_WARN(xdna, "  fw_state:           0x%x\n", hs->vm.fw_state);
	XDNA_WARN(xdna, "  abs_page_index:     0x%x\n", hs->vm.abs_page_index);
	XDNA_WARN(xdna, "  ppc:                0x%x\n", hs->vm.ppc);

	/* Dump exception info if any */
	if (hs->exception.ear || hs->exception.esr || hs->exception.pc) {
		XDNA_WARN(xdna, "Firmware Exception:\n");
		XDNA_WARN(xdna, "  EAR (addr):         0x%x\n", hs->exception.ear);
		XDNA_WARN(xdna, "  ESR (status):       0x%x\n", hs->exception.esr);
		XDNA_WARN(xdna, "  PC:                 0x%x\n", hs->exception.pc);
	}

	/* Dump firmware counters for insight into workload */
	XDNA_WARN(xdna, "Firmware Counters:\n");
	XDNA_WARN(xdna, "  c_job_launched:     %u\n", hs->counter.c_job_launched);
	XDNA_WARN(xdna, "  c_job_finished:     %u\n", hs->counter.c_job_finished);
	XDNA_WARN(xdna, "  c_hsa_pkt:          %u\n", hs->counter.c_hsa_pkt);
	XDNA_WARN(xdna, "  c_opcode:           %u\n", hs->counter.c_opcode);
	XDNA_WARN(xdna, "  c_doorbell:         %u\n", hs->counter.c_doorbell);
	XDNA_WARN(xdna, "  c_page:             %u\n", hs->counter.c_page);

	/* Dump DMA addresses for debugging DMA errors */
	XDNA_WARN(xdna, "Last DMA Addresses:\n");
	XDNA_WARN(xdna, "  dm2mm:              0x%x%08x\n",
		  hs->last_ddr_dm2mm_addr_high, hs->last_ddr_dm2mm_addr_low);
	XDNA_WARN(xdna, "  mm2dm:              0x%x%08x\n",
		  hs->last_ddr_mm2dm_addr_high, hs->last_ddr_mm2dm_addr_low);

	/* Dump context save/restore state */
	XDNA_WARN(xdna, "Context Save State:\n");
	XDNA_WARN(xdna, "  restore_page_idx:   %u\n",
		  hs->ctx_save.contents.restore_page.page_index);
	XDNA_WARN(xdna, "  cmd_chain_failure:  %u\n",
		  hs->ctx_save.contents.restore_page.cmd_chain_failure);

	XDNA_WARN(xdna, "=== VE2 DEBUG DUMP END ===\n");
	kfree(hs);
}

static void ve2_aie_error_cb(void *arg)
{
	struct amdxdna_mgmtctx *mgmtctx = arg;
	struct aie_errors *aie_errs;
	struct amdxdna_dev *xdna;
	int i;

	if (!mgmtctx) {
		pr_err("%s: mgmt hwctx is not initialized\n", __func__);
		return;
	}

	xdna = mgmtctx->xdna;
	/* Mark error callback as in progress */
	atomic_set(&mgmtctx->error_cb_in_progress, 1);
	reinit_completion(&mgmtctx->error_cb_completion);

	mutex_lock(&mgmtctx->ctx_lock);

	if (!mgmtctx->mgmt_aiedev) {
		XDNA_ERR(xdna, "%s: AIE partition is not loaded\n", __func__);
		mutex_unlock(&mgmtctx->ctx_lock);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);
		complete(&mgmtctx->error_cb_completion);
		return;
	}
	aie_errs = aie_get_errors(mgmtctx->mgmt_aiedev);
	if (IS_ERR_OR_NULL(aie_errs)) {
		XDNA_ERR(xdna, "%s: aie_get_errors returns NULL\n", __func__);
		mutex_unlock(&mgmtctx->ctx_lock);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);
		complete(&mgmtctx->error_cb_completion);
		return;
	}

	/* Cache the last async error FIRST, before logging, to ensure user space
	 * queries can find it immediately even if logging hasn't completed yet.
	 */
	if (aie_errs->num_err > 0) {
		struct amdxdna_async_error *record = &mgmtctx->async_errs_cache.err;
		struct aie_error *last_err = &aie_errs->errors[aie_errs->num_err - 1];
		enum amdxdna_error_num err_num;
		enum amdxdna_error_module err_mod;
		u64 err_code;
		u64 current_time_us = ktime_to_us(ktime_get_real());

		/* Convert category to amdxdna error number */
		switch (last_err->category) {
		case 0: /* AIE_ERROR_SATURATION */
			err_num = AMDXDNA_ERROR_NUM_AIE_SATURATION;
			break;
		case 1: /* AIE_ERROR_FP */
			err_num = AMDXDNA_ERROR_NUM_AIE_FP;
			break;
		case 2: /* AIE_ERROR_STREAM */
			err_num = AMDXDNA_ERROR_NUM_AIE_STREAM;
			break;
		case 3: /* AIE_ERROR_ACCESS */
			err_num = AMDXDNA_ERROR_NUM_AIE_ACCESS;
			break;
		case 4: /* AIE_ERROR_BUS */
			err_num = AMDXDNA_ERROR_NUM_AIE_BUS;
			break;
		case 5: /* AIE_ERROR_INSTRUCTION */
			err_num = AMDXDNA_ERROR_NUM_AIE_INSTRUCTION;
			break;
		case 6: /* AIE_ERROR_ECC */
			err_num = AMDXDNA_ERROR_NUM_AIE_ECC;
			break;
		case 7: /* AIE_ERROR_LOCK */
			err_num = AMDXDNA_ERROR_NUM_AIE_LOCK;
			break;
		case 8: /* AIE_ERROR_DMA */
			err_num = AMDXDNA_ERROR_NUM_AIE_DMA;
			break;
		case 9: /* AIE_ERROR_MEM_PARITY */
			err_num = AMDXDNA_ERROR_NUM_AIE_MEM_PARITY;
			break;
		default:
			err_num = AMDXDNA_ERROR_NUM_UNKNOWN;
			break;
		}

		/* Convert module to amdxdna error module */
		switch (last_err->module) {
		case 0: /* AIE_MEM_MOD */
			err_mod = AMDXDNA_ERROR_MODULE_AIE_MEMORY;
			break;
		case 1: /* AIE_CORE_MOD */
			err_mod = AMDXDNA_ERROR_MODULE_AIE_CORE;
			break;
		case 2: /* AIE_PL_MOD */
			err_mod = AMDXDNA_ERROR_MODULE_AIE_PL;
			break;
		default:
			err_mod = AMDXDNA_ERROR_MODULE_UNKNOWN;
			break;
		}

		err_code = AMDXDNA_CRITICAL_ERROR_CODE_BUILD(err_num, err_mod);

		mutex_lock(&mgmtctx->async_errs_cache.lock);
		record->ts_us = current_time_us;
		record->err_code = err_code;
		record->ex_err_code = AMDXDNA_ERROR_EXTRA_CODE_BUILD(last_err->loc.row,
								     last_err->loc.col);
		mutex_unlock(&mgmtctx->async_errs_cache.lock);
	}

	/* Log error details after caching to ensure cache is available for queries */
	for (i = 0; i < aie_errs->num_err; i++) {
		XDNA_DBG(xdna, "Display AIE asynchronous Error data:\n");
		XDNA_DBG(xdna, "error_id %d Mod %d, category %d, Col %d, Row %d\n",
			 aie_errs->errors[i].error_id,
			 aie_errs->errors[i].module,
			 aie_errs->errors[i].category,
			 aie_errs->errors[i].loc.col,
			 aie_errs->errors[i].loc.row);
	}

	aie_free_errors(aie_errs);

	/* Dump HSA queue and handshake data for debugging */
	if (verbosity >= VERBOSITY_LEVEL_DBG)
		ve2_dump_debug_state(xdna, mgmtctx);

	/*
	 * Optional delay for devmem debugging - allows user to dump debug information.
	 * Set via: echo N > /sys/module/amdxdna/parameters/aie_error_delay_sec
	 * Release ctx_lock before sleeping to avoid blocking other threads.
	 */
	if (aie_error_delay_sec > 0) {
		XDNA_WARN(xdna, "*** WAITING %d SECONDS ***\n", aie_error_delay_sec);
		mutex_unlock(&mgmtctx->ctx_lock);
		ssleep(aie_error_delay_sec);
		mutex_lock(&mgmtctx->ctx_lock);
		XDNA_WARN(xdna, "*** WAIT COMPLETE, RESUMING ***\n");
	}

	/*
	 * Set misc_intrpt_flag and wake up waiting threads so they don't hang
	 * indefinitely when an AIE error occurs. This allows ve2_cmd_wait() to
	 * detect the error via check_read_index() and return with timeout status.
	 */
	if (mgmtctx->active_ctx && mgmtctx->active_ctx->priv) {
		mgmtctx->active_ctx->priv->misc_intrpt_flag = true;
		wake_up_interruptible_all(&mgmtctx->active_ctx->priv->waitq);
		XDNA_ERR(xdna, "AIE error detected, waking up waiting threads\n");
	}

	mutex_unlock(&mgmtctx->ctx_lock);

	/* Mark error callback as complete and signal waiting threads */
	atomic_set(&mgmtctx->error_cb_in_progress, 0);
	complete(&mgmtctx->error_cb_completion);
}

/**
 * ve2_create_mgmt_partition - Create and initialize a management partition for VE2 device
 * @xdna: Pointer to the AMD XDNA device structure
 * @load_act: Pointer to the XRS action load structure containing partition info
 *
 * This function sets up the management context, requests the AIE partition if needed,
 * initializes workqueues for command scheduling, and updates context pointers.
 * Returns 0 on success or a negative error code on failure.
 */
static struct amdxdna_mgmtctx *
ve2_create_mgmt_partition(struct amdxdna_dev *xdna,
                         struct xrs_action_load *load_act)
{
	struct aie_partition_req request = { 0 };
	u32 start_col = load_act->part.start_col;
	struct amdxdna_mgmtctx  *mgmtctx =
		&xdna->dev_handle->ve2_mgmtctx[start_col];
	int ret = 0;

	/* Check if partition ALREADY exists (lazy reclamation case: nshared went 0→1) */
	/* Must match BOTH start_col AND ncols */
	if (mgmtctx->mgmt_aiedev && mgmtctx->ncol == load_act->part.ncols) {
		/* Sequential reuse: partition exists from previous hwctx that finished */
		XDNA_DBG(xdna, "partition_reuse: [%u,%u) already exists",
			 load_act->part.start_col, load_act->part.ncols);
		/*
		 * The previous hwctx released this partition via ve2_xrs_release()
		 * which sets is_partition_idle=1.  If we don't clear that flag here,
		 * ve2_try_reclaim_for_allocation() PASS-1 will immediately see the
		 * reused partition as "idle" and reclaim it from the new owner —
		 * leaving nhwctx->aie_dev = NULL → crash in notify_fw_cmd_ready.
		 */
		mutex_lock(&mgmtctx->ctx_lock);
		mgmtctx->is_partition_idle      = 0;
		mgmtctx->is_context_req         = 0;
		mgmtctx->is_idle_due_to_context = 0;
		mutex_unlock(&mgmtctx->ctx_lock);
		return mgmtctx;
	}

	/* If mgmt_aiedev exists but ncols doesn't match, this is a different partition size */
	/* The old partition must be destroyed before creating new one at same start_col */
	if (mgmtctx->mgmt_aiedev) {
		XDNA_ERR(xdna, "partition_create: size mismatch [%u,%u) vs [%u,%u)",
			 load_act->part.start_col, mgmtctx->ncol,
			 load_act->part.start_col, load_act->part.ncols);
		return NULL;
	}

	if (load_act->create_aie_part) {
		/* XRS says: Create NEW partition (brand new, not lazy reclaim reuse) */
		XDNA_DBG(xdna, "partition_create: creating [%u,%u)",
			 load_act->part.start_col, load_act->part.ncols);

		request.user_event1_complete = ve2_irq_handler;
		request.user_event1_priv = mgmtctx;
		request.partition_id = aie_calc_part_id(load_act->part.start_col,
							load_act->part.ncols);

		mgmtctx->mgmt_aiedev = aie_partition_request(&request);
		if (IS_ERR(mgmtctx->mgmt_aiedev)) {
			XDNA_ERR(xdna, "aie partition request failed for part id %d",
				 request.partition_id);
			mgmtctx->mgmt_aiedev = NULL;
			return NULL;
		}

		mgmtctx->xdna = xdna;
		mgmtctx->mgmt_partid = request.partition_id;
		mgmtctx->start_col = load_act->part.start_col;
		mgmtctx->ncol = load_act->part.ncols;
		mgmtctx->args.locs = NULL;
		mgmtctx->args.num_tiles = 0;

		/*
		 * Reset all scheduler-state flags carried over from the
		 * previous lifetime of this mgmtctx slot.
		 *
		 * ve2_mgmt_destroy_partition() clears active_ctx and
		 * mgmt_aiedev but intentionally leaves the rest so that
		 * cancel_work_sync / destroy_workqueue can finish cleanly.
		 * When a brand-new partition is created here those stale
		 * values become dangerous:
		 *
		 *   is_partition_idle = 1  (set by ve2_detach_hwctx_from_partition
		 *                           during cooperative reclaim)
		 *
		 * Without this reset, PASS-1 in ve2_try_reclaim_for_allocation
		 * sees the freshly-created partition as "already idle" and
		 * immediately reclaims it from the hwctx that just obtained it,
		 * leaving nhwctx->aie_dev = NULL → NULL-deref in
		 * notify_fw_cmd_ready (ve2_partition_write NULL+0x48 oops).
		 */
		mgmtctx->active_ctx             = NULL;
		mgmtctx->is_partition_idle      = 0;
		mgmtctx->is_context_req         = 0;
		mgmtctx->is_idle_due_to_context = 0;

		mutex_init(&mgmtctx->ctx_lock);
		mutex_init(&mgmtctx->async_errs_cache.lock);
		memset(&mgmtctx->async_errs_cache.err, 0, sizeof(mgmtctx->async_errs_cache.err));
		init_completion(&mgmtctx->error_cb_completion);
		atomic_set(&mgmtctx->error_cb_in_progress, 0);
		INIT_LIST_HEAD(&mgmtctx->ctx_command_fifo_head);
		/* Create workqueue for scheduling the command */
		mgmtctx->mgmtctx_workq = create_workqueue("ve2_mgmtctx_scheduler");
		if (!mgmtctx->mgmtctx_workq) {
			XDNA_ERR(xdna, "Failed to create Workqueue for scheduler");
			aie_partition_release(mgmtctx->mgmt_aiedev);
			return NULL;
		}

		INIT_WORK(&mgmtctx->sched_work, ve2_scheduler_work);
		/* Register AIE error call back function. */
		ret = aie_register_error_notification(mgmtctx->mgmt_aiedev, ve2_aie_error_cb, mgmtctx);
		XDNA_DBG(xdna, "Registered AIE error callback, ret=%d", ret);
	}

	return mgmtctx;
}

// we split ve2_partition_read into multiple call for mem and core tile till aie driver provide
// api to read complete 1MB address space
int ve2_create_coredump(struct amdxdna_dev *xdna,
			struct amdxdna_ctx *hwctx,
			void *buffer,
			u32 size)
{
	struct amdxdna_ctx_priv *nhwctx = hwctx->priv;
	struct amdxdna_mgmtctx  *mgmtctx =
		&xdna->dev_handle->ve2_mgmtctx[start_col];
	struct device *aie_dev = mgmtctx->mgmt_aiedev;
	int rel_size = 0;

	if (mgmtctx->active_ctx != hwctx) {
		if (mgmtctx->active_ctx) {
			XDNA_ERR(xdna,
				 "Cannot get coredump: hwctx %u (pid %u) is not the last scheduled. The last scheduled hwctx was %u (pid %u).\n",
				 hwctx->id, hwctx->client->pid,
				 mgmtctx->active_ctx->id, mgmtctx->active_ctx->client->pid);
		} else {
			XDNA_ERR(xdna,
				 "Cannot get coredump: No context has been scheduled yet. Please run a workload before requesting coredump.\n");
		}
		return -EPERM;
	}

	XDNA_DBG(xdna, "Reading coredump for hwctx num_col:%d\n", nhwctx->num_col);
	rel_size = ve2_partition_coredump(aie_dev, size, buffer);
	if (rel_size < 0) {
		XDNA_ERR(xdna, "Failed to read coredump, err:%d\n", rel_size);
		return -EINVAL;
	}
	XDNA_DBG(xdna, "Reading coredump ret:%d\n", rel_size);

	return rel_size;
}

/* Unused for lazy reclamation - partitions cleared on destroy */
#if 0
static void cert_clear_partition(struct amdxdna_dev *xdna, struct amdxdna_ctx_priv *nhwctx)
{
	struct device *aie_dev = nhwctx->aie_dev;
	u32 num_col = nhwctx->num_col;
	int ret = 0;
	struct aie_op_handshake_data *hs_data;

	hs_data = ve2_prepare_hs_data(xdna, nhwctx, false);
	if (!hs_data) {
		XDNA_ERR(xdna, "No memory for hs_data\n");
		return;
	}

	ret = aie_partition_handshake_update(aie_dev, hs_data, num_col);
	if (ret < 0)
		XDNA_ERR(xdna, "aie partition handshake update failed, ret: %d\n", ret);
	ve2_free_hs_data(hs_data, num_col);
}
#endif

int ve2_xrs_release(struct amdxdna_dev *xdna, struct amdxdna_ctx *hwctx)
{
        struct solver_state *xrs = xdna->dev_handle->xrs_hdl;
        struct amdxdna_ctx_priv *nhwctx = hwctx->priv;
        struct amdxdna_mgmtctx  *mgmtctx = NULL;
        u32 start_col = nhwctx->start_col;
        struct xrs_action_load load_act;
        int ret;

        mgmtctx = &xdna->dev_handle->ve2_mgmtctx[start_col];

        mutex_lock(&xrs->xrs_lock);
	/* Release resource tracking - for lazy reclamation this doesn't destroy partition */
	ret = xrs_release_resource(xdna->dev_handle->xrs_hdl, (uintptr_t)hwctx, &load_act);
        if (ret) {
                mutex_unlock(&xrs->xrs_lock);
                /* ENOENT is expected when solver node was already freed by reclamation */
                if (ret == -ENOENT)
                        XDNA_DBG(xdna, "xrs_release: solver_node already freed (reclaimed), ret=%d", ret);
                else
                        XDNA_ERR(xdna, "xrs_release failed ret=%d", ret);
                return ret;
        }

        /* For lazy reclamation: partition stays alive, just clear active_ctx */
        mutex_lock(&mgmtctx->ctx_lock);
        if (mgmtctx->active_ctx == hwctx) {
                mgmtctx->active_ctx = NULL;
                mgmtctx->is_partition_idle = 1;
        }
        mutex_unlock(&mgmtctx->ctx_lock);
        mutex_unlock(&xrs->xrs_lock);

        return 0;
}

/*
 * ve2_force_unmap_aie_file - Destroy all VMAs in current->mm that are backed
 *                            by the given AIE partition file.
 *
 * When the shim calls mmap() on the AIE partition FD, the kernel's mmap path
 * calls get_file() on the file, raising file->f_count to 2 (1 for the FD
 * + 1 for the VMA's vm_file).  A subsequent close_fd() drops f_count back to
 * 1, but the VMA still holds it, so the file's f_op->release() is never
 * called.  That release() is what calls put_device() on the AIE partition
 * device; without it, the device refcount never reaches 0 and the AIE
 * aperture never clears the partition from its "in use" bitmap.
 *
 * By force-unmapping the VMA here (before close_fd), we drop the VMA's
 * file reference.  Then close_fd() drops f_count to 0 → release() fires →
 * put_device() → device refcount drops → aperture clears "in use".
 *
 * This only operates on current->mm, so it only helps for the common
 * single-process case where all hwctx share the same PID.
 */
static void ve2_force_unmap_aie_file(struct file *aie_file)
{
	struct mm_struct *mm = current->mm;
	struct vm_area_struct *vma;
	unsigned long start, end;

	if (!mm)
		return;

	for (;;) {
		/* Scan for a VMA backed by this file (requires at least read lock) */
		mmap_read_lock(mm);
		start = end = 0;
		for (vma = find_vma(mm, 0); vma; vma = find_vma(mm, vma->vm_end)) {
			if (vma->vm_file == aie_file) {
				start = vma->vm_start;
				end = vma->vm_end;
				break;
			}
		}
		mmap_read_unlock(mm);

		if (!start)
			break; /* No more VMAs for this file */

		pr_debug("amdxdna: ve2_force_unmap_aie_file: unmapping VMA [%lx, %lx)\n",
			 start, end);
		/* vm_munmap acquires mmap_write_lock internally; do NOT hold any mm lock here */
		vm_munmap(start, end - start);
	}
}

/*
 * ve2_xrs_reclaim_partition - Explicitly reclaim/destroy a partition
 *
 * This is called when we need to free up space for new allocations.
 * Unlike ve2_xrs_release which keeps partitions alive, this actually destroys them.
 *
 * The key challenge: aie_partition_get_fd() hands the shim an open file descriptor
 * that holds a reference to the AIE partition in the AIE driver.  The shim then
 * calls mmap() on that FD to access the AIE registers; this raises file->f_count
 * to 2 (FD + VMA).  A bare close_fd() only drops f_count to 1 – the VMA keeps
 * the file alive, the file's release() is never called, put_device() never fires,
 * and the aperture's "in use" bitmap is never cleared.
 *
 * We therefore FIRST force-unmap the VMA (ve2_force_unmap_aie_file), THEN
 * close_fd().  After both steps f_count reaches 0, release() fires, and
 * aie_partition_release() in ve2_mgmt_destroy_partition() drops the device
 * refcount to 0, letting the aperture free the columns.
 *
 * We do a global scan over ALL clients/contexts (not just mgmtctx->active_ctx)
 * because once a command completes the scheduler clears active_ctx but the hwctx
 * itself – and its open AIE FD – lives on until the application calls DESTROY_HWCTX.
 * Using nhwctx->mgmtctx as the key reliably finds every hwctx that was assigned to
 * this partition, regardless of idle/active state.
 *
 * close_fd() operates on the current task's file table, so it only works when the
 * partition owner and the requester share the same process.  For the common
 * single-process case (all hwctx in one PID) this covers every FD.
 */
int ve2_xrs_reclaim_partition(struct amdxdna_dev *xdna, u32 start_col, u32 ncols)
{
	struct solver_state *xrs = xdna->dev_handle->xrs_hdl;
	struct amdxdna_mgmtctx *mgmtctx = &xdna->dev_handle->ve2_mgmtctx[start_col];
	struct xrs_action_load load_act = {0};
	struct amdxdna_client *client;
	struct amdxdna_ctx_priv *nhwctx;
	struct amdxdna_ctx *hwctx;
	unsigned long hwctx_id;
	int idx, ret;

	/*
	 * Step 1: Global scan – for every hwctx currently assigned to this
	 * partition (identified by nhwctx->mgmtctx == mgmtctx):
	 *   a) Close the shim-side AIE FD so aie_partition_release() can
	 *      actually free the partition (drop the FD reference).
	 *   b) Clear start_col/num_col so ve2_hwctx_fini() won't try to call
	 *      ve2_xrs_release() on an already-deleted solver node.
	 *
	 * This must be done WITHOUT holding mgmtctx->ctx_lock to avoid deadlock
	 * with the srcu read lock (the comment in amdxdna_drm.h forbids waiting
	 * on srcu while dev_lock/ctx_lock is held in some paths).
	 */
	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->ctx_srcu);
		amdxdna_for_each_ctx(client, hwctx_id, hwctx) {
			if (!hwctx->priv)
				continue;
			nhwctx = hwctx->priv;
			if (nhwctx->mgmtctx != mgmtctx)
				continue;

			/* Clear XRS fields – prevents double-release in hwctx_fini */
			nhwctx->start_col = 0;
			nhwctx->num_col = 0;

			/*
			 * Clear mgmtctx and aie_dev now, BEFORE the partition
			 * device is released in Step 3.
			 *
			 * ve2_mgmt_destroy_partition() calls aie_partition_release()
			 * → __fput_sync(apart->filep) → aie_part_release() →
			 * aie_part_remove() → device_del() (devres freed, pkt_va
			 * PTE cleared) + devm_kfree(apart) (struct freed).
			 *
			 * After that, nhwctx->aie_dev = &apart->dev is a dangling
			 * pointer.  If the scheduler runs for this hwctx and finds
			 * nhwctx->mgmtctx != NULL it skips ve2_xrs_request() and
			 * calls ve2_mgmt_handshake_init(nhwctx->aie_dev) on the
			 * freed struct → use-after-free → oops in aie_part_pm_ops.
			 *
			 * Setting both to NULL forces the scheduler to call
			 * ve2_xrs_request() which will assign a new (valid)
			 * partition before any AIE operations are attempted.
			 */
			nhwctx->mgmtctx = NULL;
			nhwctx->aie_dev  = NULL;

			/*
			 * Close the shim-side AIE FD so the AIE driver can
			 * deregister the partition from the aperture.
			 *
			 * Two references keep the file alive:
			 *   1) The open FD entry in the process file table
			 *   2) The VMA created when the shim called mmap() on
			 *      the FD to access the AIE registers (XAie init)
			 *
			 * close_fd() alone only drops (1).  The VMA holds (2)
			 * and prevents f_count from reaching 0, so the file's
			 * release() — which calls put_device() on the partition —
			 * is never invoked.  Without that, aie_partition_release()
			 * never reaches refcount=0 and the aperture keeps the
			 * columns marked "in use".
			 *
			 * Solution: force-unmap the VMA first, then close the FD.
			 * After both steps, f_count==0 → release() fires →
			 * put_device() → aperture clears the "in use" bitmap.
			 *
			 * close_fd() / vm_munmap() only operate on current->mm;
			 * skip if the owning process is different.
			 */
			if (nhwctx->aie_part_fd >= 0 &&
			    client->pid == task_pid_vnr(current)) {
				struct file *aie_file = fget(nhwctx->aie_part_fd);

				if (aie_file) {
					ve2_force_unmap_aie_file(aie_file);
					fput(aie_file);
				}
				XDNA_DBG(xdna,
					 "reclaim: closing aie_part_fd=%d hwctx id=%u pid=%d",
					 nhwctx->aie_part_fd, hwctx->id, client->pid);
				close_fd(nhwctx->aie_part_fd);
				nhwctx->aie_part_fd = -1;
			}
		}
		srcu_read_unlock(&client->ctx_srcu, idx);
	}

	/* Step 2: Forcefully reclaim XRS tracking (deletes solver nodes) */
	mutex_lock(&xrs->xrs_lock);
	ret = xrs_reclaim_partition(xrs, start_col, ncols, &load_act);
	mutex_unlock(&xrs->xrs_lock);

	if (ret) {
		XDNA_ERR(xdna, "xrs_reclaim failed ret=%d", ret);
		return ret;
	}

	/* Step 3: Destroy the AIE partition – now safe, all FD refs are gone */
	ve2_mgmt_destroy_partition(mgmtctx);

	return 0;
}

/**
 * ve2_mgmt_destroy_partition - Destroys a VE2 management partition and releases
 *                              associated resources.
 * @mgmtctx: Pointer to the Management context to be destroyed.
 *
 * This function tearsdown and releases the AIE partition, and updates the management context.
 * It should be called when a hardware context is no longer needed.
 */
void ve2_mgmt_destroy_partition(struct amdxdna_mgmtctx  *mgmtctx)
{
        struct amdxdna_dev *xdna = mgmtctx->xdna;
        struct workqueue_struct *wq = NULL;

        if (IS_ERR_OR_NULL(mgmtctx->mgmt_aiedev)) {
                pr_warn("amdxdna: partition_destroy [%u,%u) skipped – aiedev is %s\n",
                        mgmtctx->start_col, mgmtctx->ncol,
                        mgmtctx->mgmt_aiedev ? "ERR_PTR" : "NULL");
                return;
        }

        XDNA_DBG(xdna, "partition_destroy: [%u,%u)", mgmtctx->start_col, mgmtctx->ncol);

        mutex_lock(&mgmtctx->ctx_lock);
        /* Save wq BEFORE clearing it, then cancel pending work outside the lock */
        wq = mgmtctx->mgmtctx_workq;
        mgmtctx->mgmtctx_workq = NULL;
        mgmtctx->active_ctx = NULL;
        mutex_unlock(&mgmtctx->ctx_lock);

        /* Cancel any pending partition work before destroying it.
         * Must be done outside ctx_lock to avoid deadlock with sched_work
         * which also acquires ctx_lock. This ensures aie_partition_release()
         * is only called after all scheduler work referencing this partition
         * has completed.
         */
        if (wq) {
                cancel_work_sync(&mgmtctx->sched_work);
                destroy_workqueue(wq);
        }

        aie_unregister_error_notification(mgmtctx->mgmt_aiedev);
        aie_partition_teardown(mgmtctx->mgmt_aiedev);
        aie_partition_release(mgmtctx->mgmt_aiedev);

        /* Clear mgmt_aiedev so ve2_create_mgmt_partition() knows partition is gone */
        mgmtctx->mgmt_aiedev = NULL;
}

struct amdxdna_ctx *ve2_get_hwctx(struct amdxdna_dev *xdna, u32 col)
{
	struct amdxdna_client *client;
	struct amdxdna_ctx *hwctx;
	unsigned long hwctx_id;
	u32 start, end;
	int idx;

	list_for_each_entry(client, &xdna->client_list, node) {
		idx = srcu_read_lock(&client->ctx_srcu);
		amdxdna_for_each_ctx(client, hwctx_id, hwctx) {
			start = hwctx->start_col;
			end = start + hwctx->num_col;
			if (col >= start && col < end) {
				XDNA_DBG(xdna, "hwctx found with id %d & pid %d\n",
					 hwctx->id, hwctx->client->pid);
				srcu_read_unlock(&client->ctx_srcu, idx);
				return hwctx;
			}
		}
		srcu_read_unlock(&client->ctx_srcu, idx);
	}

	XDNA_ERR(xdna, "hwctx not found for requested col: %d\n", col);

	return NULL;
}

/*
 * notify_fw_cmd_ready - Notify the firmware that a new command is ready for execution
 * @hwctx: Pointer to the hardware context associated with the command
 *
 * This function writes to the event generation register to signal the firmware
 * that a command is ready to be processed for the specified hardware context.
 * Returns 0 on success or a negative error code on failure.
 */
int notify_fw_cmd_ready(struct amdxdna_ctx *hwctx)
{
	struct amdxdna_dev *xdna = hwctx->client->xdna;
	u32 value = VE2_USER_EVENT_ID;
	int ret;

	ret = ve2_partition_write(hwctx->priv->aie_dev, 0, 0,
				  VE2_EVENT_GENERATE_REG, sizeof(u32),
				  (void *)&(value));
	if (ret < 0)
		XDNA_ERR(xdna, "Failed to write event_generate register, err=%d", ret);

	return ret;
}
