/** @file
  This file defines the EDKII IPv6 Router Advertisement Info Protocol.

  Copyright (c) 2026, Red Hat, Inc. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef EDKII_IP6_RA_INFO_H_
#define EDKII_IP6_RA_INFO_H_

#define EDKII_IP6_RA_INFO_PROTOCOL_GUID \
  { \
    0x64f2aae2, 0xc7ab, 0x475d, { 0xba, 0x98, 0xaa, 0x9c, 0xb0, 0x69, 0xa5, 0x08 } \
  }

typedef struct _EDKII_IP6_RA_INFO_PROTOCOL EDKII_IP6_RA_INFO_PROTOCOL;

///
/// Information from the latest valid Router Advertisement accepted by Ip6Dxe.
///
typedef struct {
  BOOLEAN    Received;
  BOOLEAN    ManagedFlag;
  BOOLEAN    OtherConfigFlag;
} EDKII_IP6_RA_INFO;

/**
  Get the latest Router Advertisement M/O flag information.

  @param[in]  This    Pointer to the EDKII_IP6_RA_INFO_PROTOCOL instance.
  @param[out] RaInfo  Pointer to the buffer to receive Router Advertisement info.

  @retval EFI_SUCCESS            Router Advertisement info is returned.
  @retval EFI_INVALID_PARAMETER  This or RaInfo is NULL.
  @retval EFI_NOT_READY          No valid Router Advertisement has been received.

**/
typedef
EFI_STATUS
(EFIAPI *EDKII_IP6_RA_INFO_GET_LATEST)(
  IN  EDKII_IP6_RA_INFO_PROTOCOL  *This,
  OUT EDKII_IP6_RA_INFO           *RaInfo
  );

///
/// EDKII IPv6 Router Advertisement Info Protocol.
///
struct _EDKII_IP6_RA_INFO_PROTOCOL {
  EDKII_IP6_RA_INFO_GET_LATEST    GetLatestRaInfo;
};

extern EFI_GUID  gEdkiiIp6RaInfoProtocolGuid;

#endif
