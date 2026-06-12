// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2025, Advanced Micro Devices, Inc. All rights reserved.

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/optional.hpp>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <iostream>

#include "core/edge/common/aie_parser.h"
#include "core/edge/user/hwctx_object.h"
#include "xaiengine/xlnx-ai-engine.h"
#include "shim_debug.h"
#include "xdna_aie_array.h"
#include "xdna_device.h"
#include "xdna_hwctx.h"

namespace shim_xdna_edge {

namespace pt = boost::property_tree;
void read_aie_metadata(const char* data, size_t size, pt::ptree& aie_project)
{
  std::stringstream aie_stream;
  aie_stream.write(data,size);
  pt::read_json(aie_stream,aie_project);
}

adf::driver_config
get_driver_config(const pt::ptree& aie_meta)
{
  adf::driver_config driver_config;
  driver_config.hw_gen = aie_meta.get<uint8_t>("aie_metadata.driver_config.hw_gen");
  driver_config.base_address = aie_meta.get<uint64_t>("aie_metadata.driver_config.base_address");
  driver_config.column_shift = aie_meta.get<uint8_t>("aie_metadata.driver_config.column_shift");
  driver_config.row_shift = aie_meta.get<uint8_t>("aie_metadata.driver_config.row_shift");
  driver_config.num_columns = aie_meta.get<uint8_t>("aie_metadata.driver_config.num_columns");
  driver_config.num_rows = aie_meta.get<uint8_t>("aie_metadata.driver_config.num_rows");
  driver_config.shim_row = aie_meta.get<uint8_t>("aie_metadata.driver_config.shim_row");
  if (!aie_meta.get_optional<uint8_t>("aie_metadata.driver_config.mem_tile_row_start") ||
      !aie_meta.get_optional<uint8_t>("aie_metadata.driver_config.mem_tile_num_rows")) {
    driver_config.mem_row_start = aie_meta.get<uint8_t>("aie_metadata.driver_config.reserved_row_start");
    driver_config.mem_num_rows = aie_meta.get<uint8_t>("aie_metadata.driver_config.reserved_num_rows");
  }
  else {
    driver_config.mem_row_start = aie_meta.get<uint8_t>("aie_metadata.driver_config.mem_tile_row_start");
    driver_config.mem_num_rows = aie_meta.get<uint8_t>("aie_metadata.driver_config.mem_tile_num_rows");
  }
  driver_config.aie_tile_row_start = aie_meta.get<uint8_t>("aie_metadata.driver_config.aie_tile_row_start");
  driver_config.aie_tile_num_rows = aie_meta.get<uint8_t>("aie_metadata.driver_config.aie_tile_num_rows");
  return driver_config;
}

int
xdna_aie_array::
get_aie_partition_fd(const xdna_hwctx* hwctx_obj)
{
  int aie_fd = -1;
  auto dev = const_cast<xdna_hwctx*>(hwctx_obj)->get_device();

  amdxdna_drm_get_array arg = {};
  arg.param = DRM_AMDXDNA_HWCTX_AIE_PART_FD;
  arg.element_size = sizeof(aie_fd);
  arg.num_element = hwctx_obj->get_slotidx();  /* hwctx handle passed via num_element */
  arg.buffer = reinterpret_cast<uintptr_t>(&aie_fd);

  dev->get_edev()->ioctl(DRM_IOCTL_AMDXDNA_GET_ARRAY, &arg);

  return aie_fd;
}

xdna_aie_array::
xdna_aie_array(const xrt_core::device* device)
{
  dev_inst_obj = {0};
  dev_inst = nullptr;
  adf::driver_config driver_config = xrt_core::edge::aie::get_driver_config(device);

  XAie_SetupConfig(ConfigPtr,
      driver_config.hw_gen,
      driver_config.base_address,
      driver_config.column_shift,
      driver_config.row_shift,
      driver_config.num_columns,
      driver_config.num_rows,
      driver_config.shim_row,
      driver_config.mem_row_start,
      driver_config.mem_num_rows,
      driver_config.aie_tile_row_start,
      driver_config.aie_tile_num_rows);

  int RC = XAie_GetPartitionFdList(&dev_inst_obj);

  if (RC != XAIE_OK) 
    throw xrt_core::error(RC, std::string("XAie_GetPartitionFdList failed (rc=") +
                          std::to_string(RC) + ")");

  XAie_List *NodePtr;
  XAie_PartitionList *ListNode;

  NodePtr = (XAie_List *)&dev_inst_obj.PartitionList.Next->Next;

  ListNode = (XAie_PartitionList *)XAIE_CONTAINER_OF(NodePtr, XAie_PartitionList, Node);

  int aie_part_fd = ListNode->PartitionFd;

  if (aie_part_fd < 0)
    throw xrt_core::error(aie_part_fd, std::string("AIE partition fd is negative: ") +
                          std::to_string(aie_part_fd));

  fd = aie_part_fd;
  ConfigPtr.PartProp.Handle = fd;

  AieRC rc;
  if ((rc = XAie_CfgInitialize(&dev_inst_obj, &ConfigPtr)) != XAIE_OK)
    throw xrt_core::error(-EINVAL, std::string("Failed to initialize AIE configuration (rc=") +
                          std::to_string(rc) + ", err=" + std::to_string(EINVAL) + ": " +
                          errno_to_str(EINVAL) + ")");

  dev_inst = &dev_inst_obj;
}

xdna_aie_array::
xdna_aie_array(const xrt_core::device* device, const xdna_hwctx* hwctx_obj)
{
  dev_inst_obj = {0};
  dev_inst = nullptr;
  adf::driver_config driver_config = get_driver_config_hwctx(device, hwctx_obj);

  shim_debug("xdna_aie_array: driver_config: hw_gen=%u base_addr=0x%lx col_shift=%u row_shift=%u"
             " num_columns=%u num_rows=%u shim_row=%u mem_row_start=%u mem_num_rows=%u"
             " aie_tile_row_start=%u aie_tile_num_rows=%u",
             (unsigned)driver_config.hw_gen,
             (unsigned long)driver_config.base_address,
             (unsigned)driver_config.column_shift,
             (unsigned)driver_config.row_shift,
             (unsigned)driver_config.num_columns,
             (unsigned)driver_config.num_rows,
             (unsigned)driver_config.shim_row,
             (unsigned)driver_config.mem_row_start,
             (unsigned)driver_config.mem_num_rows,
             (unsigned)driver_config.aie_tile_row_start,
             (unsigned)driver_config.aie_tile_num_rows);
  std::cout << "[xdna_aie_array] driver_config:"
            << " hw_gen=" << (unsigned)driver_config.hw_gen
            << " base_addr=0x" << std::hex << driver_config.base_address << std::dec
            << " col_shift=" << (unsigned)driver_config.column_shift
            << " num_columns=" << (unsigned)driver_config.num_columns
            << " num_rows=" << (unsigned)driver_config.num_rows
            << std::endl;

  XAie_SetupConfig(ConfigPtr,
      driver_config.hw_gen,
      driver_config.base_address,
      driver_config.column_shift,
      driver_config.row_shift,
      driver_config.num_columns,
      driver_config.num_rows,
      driver_config.shim_row,
      driver_config.mem_row_start,
      driver_config.mem_num_rows,
      driver_config.aie_tile_row_start,
      driver_config.aie_tile_num_rows);

  auto part_info = hwctx_obj->get_partition_info();
  shim_debug("xdna_aie_array: part_info: partition_id=0x%x start_col=%u num_cols=%u base_addr=0x%lx"
             " (full_array_id=0x%x)",
             part_info.partition_id,
             part_info.start_column,
             part_info.num_columns,
             (unsigned long)part_info.base_address,
             xrt_core::edge::aie::full_array_id);
  std::cout << "[xdna_aie_array] part_info:"
            << " partition_id=0x" << std::hex << part_info.partition_id << std::dec
            << " start_col=" << (unsigned)part_info.start_column
            << " num_cols=" << (unsigned)part_info.num_columns
            << " base_addr=0x" << std::hex << part_info.base_address << std::dec
            << " full_array_id=0x" << std::hex << xrt_core::edge::aie::full_array_id << std::dec
            << std::endl;

  if (part_info.partition_id != xrt_core::edge::aie::full_array_id) {
    std::cout << "[xdna_aie_array] calling XAie_SetupPartitionConfig(base=0x%lx, start=%u, num=%u)"
              << " base=0x" << std::hex << part_info.base_address << std::dec
              << " start=" << (unsigned)part_info.start_column
              << " num=" << (unsigned)part_info.num_columns
              << std::endl;
    AieRC rc1;
    if ((rc1 = XAie_SetupPartitionConfig(&dev_inst_obj, part_info.base_address, part_info.start_column, part_info.num_columns)) != XAIE_OK)
      throw xrt_core::error(-EINVAL, std::string("Failed to setup AIE Partition (rc=") +
                            std::to_string(rc1) + ", err=" + std::to_string(EINVAL) + ": " +
                            errno_to_str(EINVAL) + ")");
    std::cout << "[xdna_aie_array] XAie_SetupPartitionConfig OK" << std::endl;
  } else {
    std::cout << "[xdna_aie_array] partition_id==full_array_id, skipping XAie_SetupPartitionConfig" << std::endl;
  }

  // Get AIE partition FD from kernel via ioctl
  std::cout << "[xdna_aie_array] calling get_aie_partition_fd" << std::endl;
  int aie_part_fd = get_aie_partition_fd(hwctx_obj);
  if (aie_part_fd < 0)
    throw xrt_core::error(aie_part_fd, std::string("Failed to get AIE partition FD: ") +
                          std::to_string(aie_part_fd));

  std::cout << "[xdna_aie_array] aie_part_fd=" << aie_part_fd << std::endl;
  fd = aie_part_fd;
  ConfigPtr.PartProp.Handle = fd;

  std::cout << "[xdna_aie_array] XAie_CfgInitialize: ConfigPtr.NumCols=" << (unsigned)ConfigPtr.NumCols
            << " aie_part_fd=" << aie_part_fd << std::endl;
  AieRC rc;
  if ((rc = XAie_CfgInitialize(&dev_inst_obj, &ConfigPtr)) != XAIE_OK)
    throw xrt_core::error(-EINVAL, std::string("Failed to initialize AIE configuration (rc=") +
                          std::to_string(rc) + ", err=" + std::to_string(EINVAL) + ": " +
                          errno_to_str(EINVAL) + ")");

  std::cout << "[xdna_aie_array] XAie_CfgInitialize OK" << std::endl;
  dev_inst = &dev_inst_obj;
}

xdna_aie_array::
~xdna_aie_array()
{
  if (dev_inst)
    XAie_Finish(dev_inst);
}

XAie_DevInst*
xdna_aie_array::
get_dev()
{
  if (!dev_inst)
    throw xrt_core::error(-EINVAL, std::string("AIE is not initialized (err=") +
                          std::to_string(EINVAL) + ": " + errno_to_str(EINVAL) + ")");

  return dev_inst;
}

adf::driver_config
xdna_aie_array::
get_driver_config_hwctx(const xrt_core::device* device, const xdna_hwctx* hwctx)
{
  auto xclbin_uuid = hwctx ? hwctx->get_xclbin_uuid() : xrt::uuid();
  auto data = device->get_axlf_section(AIE_TRACE_METADATA, xclbin_uuid);
  if (!data.first || !data.second)
    return {};

  pt::ptree aie_meta;
  read_aie_metadata(data.first, data.second, aie_meta);
  return get_driver_config(aie_meta);
}

} //namespace shim_xdna_edge

