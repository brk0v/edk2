/** @file
  Functions implementation related with DHCPv6 for HTTP boot driver.

Copyright (c) 2015 - 2018, Intel Corporation. All rights reserved.<BR>
Copyright (c) Microsoft Corporation
SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#include "HttpBootDxe.h"

#define HTTP_BOOT_DHCP6_SLAAC_DISCOVER_TIMEOUT  6
#define HTTP_BOOT_DHCP6_INFO_REQ_TIMEOUT        6

typedef struct {
  HTTP_BOOT_PRIVATE_DATA    *Private;
  BOOLEAN                   Accepted;
} HTTP_BOOT_DHCP6_INFO_REQUEST_CONTEXT;

typedef enum {
  HttpBootDhcp6SlaacDecisionWait,
  HttpBootDhcp6SlaacDecisionTryInfoRequest
} HTTP_BOOT_DHCP6_SLAAC_DECISION;

STATIC
EFI_STATUS
HttpBootGetSlaacPrefixLength (
  IN  HTTP_BOOT_PRIVATE_DATA  *Private,
  IN  EFI_IPv6_ADDRESS        *Ip6Addr,
  OUT UINT8                   *PrefixLength
  );

/**
  Validate that a DHCPv6 option buffer is well-formed.

  @param[in]  Buffer        The pointer to the option buffer.
  @param[in]  Length        Length of the option buffer.

  @retval     TRUE          The option buffer is well-formed.
  @retval     FALSE         The option buffer is malformed.

**/
STATIC
BOOLEAN
HttpBootIsDhcp6OptionListValid (
  IN UINT8   *Buffer,
  IN UINT32  Length
  )
{
  EFI_DHCP6_PACKET_OPTION  *Option;
  UINT32                   Offset;
  UINT16                   OpLen;

  if ((Buffer == NULL) && (Length != 0)) {
    return FALSE;
  }

  Offset = 0;
  while (Offset < Length) {
    if (Length - Offset < sizeof (Option->OpCode) + sizeof (Option->OpLen)) {
      return FALSE;
    }

    Option = (EFI_DHCP6_PACKET_OPTION *)(Buffer + Offset);
    OpLen  = NTOHS (Option->OpLen);
    Offset += sizeof (Option->OpCode) + sizeof (Option->OpLen);

    if (OpLen > Length - Offset) {
      return FALSE;
    }

    Offset += OpLen;
  }

  return TRUE;
}

/**
  Release any DHCPv6 URI parsers cached in the shared offer buffer.

  @param[in]  Private       The pointer to HTTP BOOT driver private data.

**/
STATIC
VOID
HttpBootDhcp6FreeOfferUriParsers (
  IN HTTP_BOOT_PRIVATE_DATA  *Private
  )
{
  UINTN  Index;

  for (Index = 0; Index < HTTP_BOOT_OFFER_MAX_NUM; Index++) {
    if (Private->OfferBuffer[Index].Dhcp6.UriParser != NULL) {
      HttpUrlFreeParser (Private->OfferBuffer[Index].Dhcp6.UriParser);
      Private->OfferBuffer[Index].Dhcp6.UriParser = NULL;
    }
  }
}

/**
  Clear offer selection and cached packet state owned by the DHCPv6 path.

  @param[in]  Private       The pointer to HTTP BOOT driver private data.

**/
STATIC
VOID
HttpBootDhcp6ClearOfferState (
  IN HTTP_BOOT_PRIVATE_DATA  *Private
  )
{
  UINTN  Index;

  HttpBootDhcp6FreeOfferUriParsers (Private);

  ZeroMem (Private->OfferBuffer, sizeof (Private->OfferBuffer));
  for (Index = 0; Index < HTTP_BOOT_OFFER_MAX_NUM; Index++) {
    Private->OfferBuffer[Index].Dhcp6.Packet.Offer.Size = HTTP_CACHED_DHCP6_PACKET_MAX_SIZE;
  }

  Private->OfferNum        = 0;
  Private->SelectIndex     = 0;
  Private->SelectProxyType = HttpOfferTypeMax;
  ZeroMem (Private->OfferCount, sizeof (Private->OfferCount));
  ZeroMem (Private->OfferIndex, sizeof (Private->OfferIndex));
}

/**
  Build the options buffer for the DHCPv6 request packet.

  @param[in]  Private             The pointer to HTTP BOOT driver private data.
  @param[out] OptList             The pointer to the option pointer array.
  @param[in]  Buffer              The pointer to the buffer to contain the option list.

  @return     Index               The count of the built-in options.

**/
UINT32
HttpBootBuildDhcp6Options (
  IN  HTTP_BOOT_PRIVATE_DATA   *Private,
  OUT EFI_DHCP6_PACKET_OPTION  **OptList,
  IN  UINT8                    *Buffer
  )
{
  HTTP_BOOT_DHCP6_OPTION_ENTRY  OptEnt;
  UINT16                        Value;
  UINT32                        Index;

  Index      = 0;
  OptList[0] = (EFI_DHCP6_PACKET_OPTION *)Buffer;

  //
  // Append client option request option
  //
  OptList[Index]->OpCode = HTONS (DHCP6_OPT_ORO);
  OptList[Index]->OpLen  = HTONS (8);
  OptEnt.Oro             = (HTTP_BOOT_DHCP6_OPTION_ORO *)OptList[Index]->Data;
  OptEnt.Oro->OpCode[0]  = HTONS (DHCP6_OPT_BOOT_FILE_URL);
  OptEnt.Oro->OpCode[1]  = HTONS (DHCP6_OPT_BOOT_FILE_PARAM);
  OptEnt.Oro->OpCode[2]  = HTONS (DHCP6_OPT_DNS_SERVERS);
  OptEnt.Oro->OpCode[3]  = HTONS (DHCP6_OPT_VENDOR_CLASS);
  Index++;
  OptList[Index] = GET_NEXT_DHCP6_OPTION (OptList[Index - 1]);

  //
  // Append client network device interface option
  //
  OptList[Index]->OpCode = HTONS (DHCP6_OPT_UNDI);
  OptList[Index]->OpLen  = HTONS ((UINT16)3);
  OptEnt.Undi            = (HTTP_BOOT_DHCP6_OPTION_UNDI *)OptList[Index]->Data;

  if (Private->Nii != NULL) {
    OptEnt.Undi->Type     = Private->Nii->Type;
    OptEnt.Undi->MajorVer = Private->Nii->MajorVer;
    OptEnt.Undi->MinorVer = Private->Nii->MinorVer;
  } else {
    OptEnt.Undi->Type     = DEFAULT_UNDI_TYPE;
    OptEnt.Undi->MajorVer = DEFAULT_UNDI_MAJOR;
    OptEnt.Undi->MinorVer = DEFAULT_UNDI_MINOR;
  }

  Index++;
  OptList[Index] = GET_NEXT_DHCP6_OPTION (OptList[Index - 1]);

  //
  // Append client system architecture option
  //
  OptList[Index]->OpCode = HTONS (DHCP6_OPT_ARCH);
  OptList[Index]->OpLen  = HTONS ((UINT16)sizeof (HTTP_BOOT_DHCP6_OPTION_ARCH));
  OptEnt.Arch            = (HTTP_BOOT_DHCP6_OPTION_ARCH *)OptList[Index]->Data;
  Value                  = HTONS (EFI_HTTP_BOOT_CLIENT_SYSTEM_ARCHITECTURE);
  CopyMem (&OptEnt.Arch->Type, &Value, sizeof (UINT16));
  Index++;
  OptList[Index] = GET_NEXT_DHCP6_OPTION (OptList[Index - 1]);

  //
  // Append vendor class identify option.
  //
  OptList[Index]->OpCode       = HTONS (DHCP6_OPT_VENDOR_CLASS);
  OptList[Index]->OpLen        = HTONS ((UINT16)sizeof (HTTP_BOOT_DHCP6_OPTION_VENDOR_CLASS));
  OptEnt.VendorClass           = (HTTP_BOOT_DHCP6_OPTION_VENDOR_CLASS *)OptList[Index]->Data;
  OptEnt.VendorClass->Vendor   = HTONL (HTTP_BOOT_DHCP6_ENTERPRISE_NUM);
  OptEnt.VendorClass->ClassLen = HTONS ((UINT16)sizeof (HTTP_BOOT_CLASS_ID));
  CopyMem (
    &OptEnt.VendorClass->ClassId,
    DEFAULT_CLASS_ID_DATA,
    sizeof (HTTP_BOOT_CLASS_ID)
    );
  HttpBootUintnToAscDecWithFormat (
    EFI_HTTP_BOOT_CLIENT_SYSTEM_ARCHITECTURE,
    OptEnt.VendorClass->ClassId.ArchitectureType,
    sizeof (OptEnt.VendorClass->ClassId.ArchitectureType)
    );

  if (Private->Nii != NULL) {
    CopyMem (
      OptEnt.VendorClass->ClassId.InterfaceName,
      Private->Nii->StringId,
      sizeof (OptEnt.VendorClass->ClassId.InterfaceName)
      );
    HttpBootUintnToAscDecWithFormat (
      Private->Nii->MajorVer,
      OptEnt.VendorClass->ClassId.UndiMajor,
      sizeof (OptEnt.VendorClass->ClassId.UndiMajor)
      );
    HttpBootUintnToAscDecWithFormat (
      Private->Nii->MinorVer,
      OptEnt.VendorClass->ClassId.UndiMinor,
      sizeof (OptEnt.VendorClass->ClassId.UndiMinor)
      );
  }

  Index++;

  return Index;
}

/**
  Parse out a DHCPv6 option by OptTag, and find the position in buffer.

  @param[in]  Buffer        The pointer to the option buffer.
  @param[in]  Length        Length of the option buffer.
  @param[in]  OptTag        The required option tag.

  @retval     NULL          Failed to parse the required option.
  @retval     Others        The position of the required option in buffer.

**/
EFI_DHCP6_PACKET_OPTION *
HttpBootParseDhcp6Options (
  IN UINT8   *Buffer,
  IN UINT32  Length,
  IN UINT16  OptTag
  )
{
  EFI_DHCP6_PACKET_OPTION  *Option;
  UINT32                   Offset;
  UINT16                   OpLen;

  Offset = 0;

  //
  // OpLen and OpCode here are both stored in network order.
  //
  while (Offset < Length) {
    if (Length - Offset < sizeof (Option->OpCode) + sizeof (Option->OpLen)) {
      return NULL;
    }

    Option = (EFI_DHCP6_PACKET_OPTION *)(Buffer + Offset);
    OpLen  = NTOHS (Option->OpLen);
    Offset += sizeof (Option->OpCode) + sizeof (Option->OpLen);
    if (OpLen > Length - Offset) {
      return NULL;
    }

    if (NTOHS (Option->OpCode) == OptTag) {
      return Option;
    }

    Offset += OpLen;
  }

  return NULL;
}

/**
  Copy a DHCPv6 packet into the cache and make the BootFile URL payload safe for
  existing URI helpers that expect a NUL-terminated string.

  @param[in]  Dst          The pointer to the cache buffer for DHCPv6 packet.
  @param[in]  Src          The pointer to the DHCPv6 packet to be cached.
  @param[in]  RequireBootFileUrl
                           TRUE if the packet must include BootFile URL.

  @retval     EFI_SUCCESS          Packet is copied.
  @retval     EFI_DEVICE_ERROR     Packet is malformed or lacks required BootFile URL.
  @retval     EFI_BUFFER_TOO_SMALL Cache buffer is not big enough.

**/
STATIC
EFI_STATUS
HttpBootCacheDhcp6InfoReply (
  IN EFI_DHCP6_PACKET  *Dst,
  IN EFI_DHCP6_PACKET  *Src,
  IN BOOLEAN           RequireBootFileUrl
  )
{
  EFI_DHCP6_PACKET_OPTION  *Option;
  EFI_DHCP6_PACKET_OPTION  *NewOption;
  UINT8                    *BootFileUrl;
  UINT16                   BootFileUrlLen;
  UINT32                   Offset;
  UINT32                   NewOffset;
  UINT32                   OptionsLength;
  UINT16                   OpLen;
  UINT16                   OpCode;

  if ((Dst == NULL) || (Src == NULL) || (Src->Length < sizeof (EFI_DHCP6_HEADER))) {
    return EFI_DEVICE_ERROR;
  }

  OptionsLength = GET_DHCP6_OPTION_SIZE (Src);
  if (!HttpBootIsDhcp6OptionListValid (Src->Dhcp6.Option, OptionsLength)) {
    return EFI_DEVICE_ERROR;
  }

  if (Dst->Size <= sizeof (EFI_DHCP6_HEADER)) {
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (&Dst->Dhcp6.Header, &Src->Dhcp6.Header, sizeof (EFI_DHCP6_HEADER));

  BootFileUrl    = NULL;
  BootFileUrlLen = 0;
  Offset         = 0;
  NewOffset      = 0;
  while (Offset < OptionsLength) {
    Option = (EFI_DHCP6_PACKET_OPTION *)(Src->Dhcp6.Option + Offset);
    OpLen  = NTOHS (Option->OpLen);
    OpCode = NTOHS (Option->OpCode);

    if (OpCode == DHCP6_OPT_BOOT_FILE_URL) {
      BootFileUrl    = Option->Data;
      BootFileUrlLen = OpLen;
      Offset        += sizeof (Option->OpCode) + sizeof (Option->OpLen) + OpLen;
      continue;
    }

    if (Dst->Size - sizeof (EFI_DHCP6_HEADER) - NewOffset < sizeof (Option->OpCode) + sizeof (Option->OpLen) + OpLen) {
      return EFI_BUFFER_TOO_SMALL;
    }

    CopyMem (Dst->Dhcp6.Option + NewOffset, Option, sizeof (Option->OpCode) + sizeof (Option->OpLen) + OpLen);
    NewOffset += sizeof (Option->OpCode) + sizeof (Option->OpLen) + OpLen;
    Offset    += sizeof (Option->OpCode) + sizeof (Option->OpLen) + OpLen;
  }

  if (BootFileUrl == NULL) {
    if (RequireBootFileUrl) {
      return EFI_DEVICE_ERROR;
    }

    Dst->Length = sizeof (EFI_DHCP6_HEADER) + NewOffset;
    return EFI_SUCCESS;
  }

  if ((BootFileUrlLen == 0) ||
      (Dst->Size - sizeof (EFI_DHCP6_HEADER) - NewOffset < sizeof (NewOption->OpCode) + sizeof (NewOption->OpLen) + BootFileUrlLen + 1))
  {
    return EFI_BUFFER_TOO_SMALL;
  }

  NewOption         = (EFI_DHCP6_PACKET_OPTION *)(Dst->Dhcp6.Option + NewOffset);
  NewOption->OpCode = HTONS (DHCP6_OPT_BOOT_FILE_URL);
  NewOption->OpLen  = HTONS (BootFileUrlLen);
  CopyMem (NewOption->Data, BootFileUrl, BootFileUrlLen);
  NewOption->Data[BootFileUrlLen] = '\0';
  NewOffset                     += sizeof (NewOption->OpCode) + sizeof (NewOption->OpLen) + BootFileUrlLen;
  Dst->Length                    = sizeof (EFI_DHCP6_HEADER) + NewOffset;

  return EFI_SUCCESS;
}

/**
  Parse the cached DHCPv6 packet, including all the options.

  @param[in]  Cache6           The pointer to a cached DHCPv6 packet.
  @param[in]  AllowStatelessOffer
                              TRUE if a stateless reply without BootFile URL is
                              acceptable.

  @retval     EFI_SUCCESS      Parsed the DHCPv6 packet successfully.
  @retval     EFI_DEVICE_ERROR Failed to parse and invalid the packet.

**/
EFI_STATUS
HttpBootParseDhcp6Packet (
  IN  HTTP_BOOT_DHCP6_PACKET_CACHE  *Cache6,
  IN  BOOLEAN                       AllowStatelessOffer
  )
{
  EFI_DHCP6_PACKET         *Offer;
  EFI_DHCP6_PACKET_OPTION  **Options;
  EFI_DHCP6_PACKET_OPTION  *Option;
  HTTP_BOOT_OFFER_TYPE     OfferType;
  EFI_IPv6_ADDRESS         IpAddr;
  BOOLEAN                  IsProxyOffer;
  BOOLEAN                  IsHttpOffer;
  BOOLEAN                  IsDnsOffer;
  BOOLEAN                  IpExpressedUri;
  EFI_STATUS               Status;
  UINT32                   Offset;
  UINT32                   Length;
  UINT16                   OpLen;
  UINT16                   VendorClassLen;
  CHAR8                    *BootFileUrl;

  IsDnsOffer     = FALSE;
  IpExpressedUri = FALSE;
  IsProxyOffer   = TRUE;
  IsHttpOffer    = FALSE;
  Offer          = &Cache6->Packet.Offer;
  Options        = Cache6->OptList;

  ZeroMem (Cache6->OptList, sizeof (Cache6->OptList));

  Option = (EFI_DHCP6_PACKET_OPTION *)(Offer->Dhcp6.Option);
  Offset = 0;
  Length = GET_DHCP6_OPTION_SIZE (Offer);
  if (!HttpBootIsDhcp6OptionListValid (Offer->Dhcp6.Option, Length)) {
    return EFI_DEVICE_ERROR;
  }

  //
  // OpLen and OpCode here are both stored in network order, since they are from original packet.
  //
  while (Offset < Length) {
    if (NTOHS (Option->OpCode) == DHCP6_OPT_IA_NA) {
      Options[HTTP_BOOT_DHCP6_IDX_IA_NA] = Option;
    } else if (NTOHS (Option->OpCode) == DHCP6_OPT_BOOT_FILE_URL) {
      //
      // The server sends this option to inform the client about an URL to a boot file.
      //
      Options[HTTP_BOOT_DHCP6_IDX_BOOT_FILE_URL] = Option;
    } else if (NTOHS (Option->OpCode) == DHCP6_OPT_BOOT_FILE_PARAM) {
      Options[HTTP_BOOT_DHCP6_IDX_BOOT_FILE_PARAM] = Option;
    } else if (NTOHS (Option->OpCode) == DHCP6_OPT_VENDOR_CLASS) {
      Options[HTTP_BOOT_DHCP6_IDX_VENDOR_CLASS] = Option;
    } else if (NTOHS (Option->OpCode) == DHCP6_OPT_DNS_SERVERS) {
      Options[HTTP_BOOT_DHCP6_IDX_DNS_SERVER] = Option;
    }

    Offset += (NTOHS (Option->OpLen) + sizeof (Option->OpCode) + sizeof (Option->OpLen));
    Option  = (EFI_DHCP6_PACKET_OPTION *)(Offer->Dhcp6.Option + Offset);
  }

  //
  // The offer with assigned client address is NOT a proxy offer.
  // An ia_na option, embedded with valid ia_addr option and a status_code of success.
  //
  Option = Options[HTTP_BOOT_DHCP6_IDX_IA_NA];
  if (Option != NULL) {
    OpLen = NTOHS (Option->OpLen);
    if (OpLen < 12) {
      return EFI_DEVICE_ERROR;
    }

    Option = HttpBootParseDhcp6Options (
               Option->Data + 12,
               OpLen - 12,
               DHCP6_OPT_STATUS_CODE
               );
    if ((Option != NULL) && (NTOHS (Option->OpLen) < sizeof (UINT16))) {
      return EFI_DEVICE_ERROR;
    }

    if (((Option != NULL) && (Option->Data[0] == 0) && (Option->Data[1] == 0)) || (Option == NULL)) {
      IsProxyOffer = FALSE;
    }
  }

  //
  // The offer with "HTTPClient" is a Http offer.
  //
  Option = Options[HTTP_BOOT_DHCP6_IDX_VENDOR_CLASS];

  if ((Option != NULL) &&
      (NTOHS (Option->OpLen) >= 16))
  {
    CopyMem (&VendorClassLen, Option->Data + 4, sizeof (UINT16));
    VendorClassLen = NTOHS (VendorClassLen);
  }

  if ((Option != NULL) &&
      (NTOHS (Option->OpLen) >= 16) &&
      (VendorClassLen >= 10) &&
      (VendorClassLen <= NTOHS (Option->OpLen) - 6) &&
      (CompareMem ((Option->Data + 6), DEFAULT_CLASS_ID_DATA, 10) == 0))
  {
    IsHttpOffer = TRUE;
  }

  //
  // The offer with Domain Server is a DNS offer.
  //
  Option = Options[HTTP_BOOT_DHCP6_IDX_DNS_SERVER];
  if (Option != NULL) {
    OpLen = NTOHS (Option->OpLen);
    if (((OpLen % sizeof (EFI_IPv6_ADDRESS)) != 0) || (OpLen == 0)) {
      return EFI_DEVICE_ERROR;
    }

    IsDnsOffer = TRUE;
  }

  //
  // Http offer must have a boot URI.
  //
  if (IsHttpOffer &&
      (Options[HTTP_BOOT_DHCP6_IDX_BOOT_FILE_URL] == NULL) &&
      !AllowStatelessOffer)
  {
    return EFI_DEVICE_ERROR;
  }

  if (AllowStatelessOffer && (Options[HTTP_BOOT_DHCP6_IDX_BOOT_FILE_URL] == NULL)) {
    IsHttpOffer  = FALSE;
    IsProxyOffer = FALSE;
  }

  //
  // Try to retrieve the IP of HTTP server from URI.
  //
  if (IsHttpOffer) {
    Option = Options[HTTP_BOOT_DHCP6_IDX_BOOT_FILE_URL];
    OpLen  = NTOHS (Option->OpLen);
    if (OpLen == 0) {
      return EFI_DEVICE_ERROR;
    }

    BootFileUrl = AllocateZeroPool (OpLen + 1);
    if (BootFileUrl == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    CopyMem (BootFileUrl, Option->Data, OpLen);
    Status = HttpParseUrl (
               BootFileUrl,
               OpLen,
               FALSE,
               &Cache6->UriParser
               );
    if (EFI_ERROR (Status)) {
      FreePool (BootFileUrl);
      return EFI_DEVICE_ERROR;
    }

    Status = HttpUrlGetIp6 (
               BootFileUrl,
               Cache6->UriParser,
               &IpAddr
               );
    IpExpressedUri = !EFI_ERROR (Status);
    FreePool (BootFileUrl);
  }

  //
  // Determine offer type of the DHCPv6 packet.
  //
  if (IsHttpOffer) {
    if (IpExpressedUri) {
      if (IsProxyOffer) {
        OfferType = HttpOfferTypeProxyIpUri;
      } else {
        OfferType = IsDnsOffer ? HttpOfferTypeDhcpIpUriDns : HttpOfferTypeDhcpIpUri;
      }
    } else {
      if (!IsProxyOffer) {
        OfferType = IsDnsOffer ? HttpOfferTypeDhcpNameUriDns : HttpOfferTypeDhcpNameUri;
      } else {
        OfferType = HttpOfferTypeProxyNameUri;
      }
    }
  } else {
    if (!IsProxyOffer) {
      OfferType = IsDnsOffer ? HttpOfferTypeDhcpDns : HttpOfferTypeDhcpOnly;
    } else {
      return EFI_DEVICE_ERROR;
    }
  }

  Cache6->OfferType = OfferType;
  return EFI_SUCCESS;
}

/**
  Cache the DHCPv6 packet.

  @param[in]  Dst          The pointer to the cache buffer for DHCPv6 packet.
  @param[in]  Src          The pointer to the DHCPv6 packet to be cached.

  @retval     EFI_SUCCESS                Packet is copied.
  @retval     EFI_BUFFER_TOO_SMALL       Cache buffer is not big enough to hold the packet.

**/
EFI_STATUS
HttpBootCacheDhcp6Packet (
  IN EFI_DHCP6_PACKET  *Dst,
  IN EFI_DHCP6_PACKET  *Src
  )
{
  if (Dst->Size < Src->Length) {
    return EFI_BUFFER_TOO_SMALL;
  }

  CopyMem (&Dst->Dhcp6, &Src->Dhcp6, Src->Length);
  Dst->Length = Src->Length;

  return EFI_SUCCESS;
}

/**
  Cache all the received DHCPv6 offers, and set OfferIndex and OfferCount.

  @param[in]  Private               The pointer to HTTP_BOOT_PRIVATE_DATA.
  @param[in]  RcvdOffer             The pointer to the received offer packet.

  @retval     EFI_SUCCESS      Cache and parse the packet successfully.
  @retval     Others           Operation failed.

**/
EFI_STATUS
HttpBootCacheDhcp6Offer (
  IN HTTP_BOOT_PRIVATE_DATA  *Private,
  IN EFI_DHCP6_PACKET        *RcvdOffer
  )
{
  HTTP_BOOT_DHCP6_PACKET_CACHE  *Cache6;
  EFI_DHCP6_PACKET              *Offer;
  HTTP_BOOT_OFFER_TYPE          OfferType;
  EFI_STATUS                    Status;

  Cache6 = &Private->OfferBuffer[Private->OfferNum].Dhcp6;
  Offer  = &Cache6->Packet.Offer;

  //
  // Cache the content of DHCPv6 packet firstly.
  //
  Status = HttpBootCacheDhcp6Packet (Offer, RcvdOffer);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  //
  // Validate the DHCPv6 packet, and parse the options and offer type.
  //
  if (EFI_ERROR (HttpBootParseDhcp6Packet (Cache6, FALSE))) {
    return EFI_ABORTED;
  }

  //
  // Determine whether cache the current offer by type, and record OfferIndex and OfferCount.
  //
  OfferType = Cache6->OfferType;
  ASSERT (OfferType < HttpOfferTypeMax);
  ASSERT (Private->OfferCount[OfferType] < HTTP_BOOT_OFFER_MAX_NUM);
  Private->OfferIndex[OfferType][Private->OfferCount[OfferType]] = Private->OfferNum;
  Private->OfferCount[OfferType]++;
  Private->OfferNum++;

  return EFI_SUCCESS;
}

/**
  EFI_DHCP6_CALLBACK is provided by the consumer of the EFI DHCPv6 Protocol driver
  to intercept events that occurred in the configuration process.

  @param[in]  This              The pointer to the EFI DHCPv6 Protocol.
  @param[in]  Context           The pointer to the context set by EFI_DHCP6_PROTOCOL.Configure().
  @param[in]  CurrentState      The current operational state of the EFI DHCPv Protocol driver.
  @param[in]  Dhcp6Event        The event that occurs in the current state, which usually means a
                                state transition.
  @param[in]  Packet            The DHCPv6 packet that is going to be sent or was already received.
  @param[out] NewPacket         The packet that is used to replace the Packet above.

  @retval EFI_SUCCESS           Told the EFI DHCPv6 Protocol driver to continue the DHCP process.
  @retval EFI_NOT_READY         Only used in the Dhcp6Selecting state. The EFI DHCPv6 Protocol
                                driver will continue to wait for more packets.
  @retval EFI_ABORTED           Told the EFI DHCPv6 Protocol driver to abort the current process.
  @retval EFI_OUT_OF_RESOURCES  There are not enough resources.

**/
EFI_STATUS
EFIAPI
HttpBootDhcp6CallBack (
  IN  EFI_DHCP6_PROTOCOL  *This,
  IN  VOID                *Context,
  IN  EFI_DHCP6_STATE     CurrentState,
  IN  EFI_DHCP6_EVENT     Dhcp6Event,
  IN  EFI_DHCP6_PACKET    *Packet,
  OUT EFI_DHCP6_PACKET    **NewPacket     OPTIONAL
  )
{
  HTTP_BOOT_PRIVATE_DATA  *Private;
  EFI_DHCP6_PACKET        *SelectAd;
  EFI_STATUS              Status;
  BOOLEAN                 Received;

  if ((Dhcp6Event != Dhcp6SendSolicit) &&
      (Dhcp6Event != Dhcp6RcvdAdvertise) &&
      (Dhcp6Event != Dhcp6SendRequest) &&
      (Dhcp6Event != Dhcp6RcvdReply) &&
      (Dhcp6Event != Dhcp6SelectAdvertise))
  {
    return EFI_SUCCESS;
  }

  ASSERT (Packet != NULL);

  Private = (HTTP_BOOT_PRIVATE_DATA *)Context;
  Status  = EFI_SUCCESS;
  if ((Private->HttpBootCallback != NULL) && (Dhcp6Event != Dhcp6SelectAdvertise)) {
    Received = (BOOLEAN)(Dhcp6Event == Dhcp6RcvdAdvertise || Dhcp6Event == Dhcp6RcvdReply);
    Status   = Private->HttpBootCallback->Callback (
                                            Private->HttpBootCallback,
                                            HttpBootDhcp6,
                                            Received,
                                            Packet->Length,
                                            &Packet->Dhcp6
                                            );
    if (EFI_ERROR (Status)) {
      return EFI_ABORTED;
    }
  }

  switch (Dhcp6Event) {
    case Dhcp6RcvdAdvertise:
      Status = EFI_NOT_READY;
      if (Packet->Length > HTTP_BOOT_DHCP6_PACKET_MAX_SIZE) {
        //
        // Ignore the incoming packets which exceed the maximum length.
        //
        break;
      }

      if (Private->OfferNum < HTTP_BOOT_OFFER_MAX_NUM) {
        //
        // Cache the dhcp offers to OfferBuffer[] for select later, and record
        // the OfferIndex and OfferCount.
        // If error happens, just ignore this packet and continue to wait more offer.
        //
        HttpBootCacheDhcp6Offer (Private, Packet);
      }

      break;

    case Dhcp6SelectAdvertise:
      //
      // Select offer by the default policy or by order, and record the SelectIndex
      // and SelectProxyType.
      //
      HttpBootSelectDhcpOffer (Private);

      if (Private->SelectIndex == 0) {
        Status = EFI_ABORTED;
      } else {
        ASSERT (NewPacket != NULL);
        SelectAd   = &Private->OfferBuffer[Private->SelectIndex - 1].Dhcp6.Packet.Offer;
        *NewPacket = AllocateZeroPool (SelectAd->Size);
        if (*NewPacket == NULL) {
          return EFI_OUT_OF_RESOURCES;
        }

        CopyMem (*NewPacket, SelectAd, SelectAd->Size);
      }

      break;

    default:
      break;
  }

  return Status;
}

/**
  Check whether IP driver could route the message which will be sent to ServerIp address.

  This function will check the IP6 route table every 1 seconds until specified timeout is expired, if a valid
  route is found in IP6 route table, the address will be filed in GatewayAddr and return.

  @param[in]  Private             The pointer to HTTP_BOOT_PRIVATE_DATA.
  @param[in]  TimeOutInSecond     Timeout value in seconds.
  @param[out] GatewayAddr         Pointer to store the gateway IP address.

  @retval     EFI_SUCCESS         Found a valid gateway address successfully.
  @retval     EFI_TIMEOUT         The operation is time out.
  @retval     Other               Unexpected error happened.

**/
EFI_STATUS
HttpBootCheckRouteTable (
  IN  HTTP_BOOT_PRIVATE_DATA  *Private,
  IN  UINTN                   TimeOutInSecond,
  OUT EFI_IPv6_ADDRESS        *GatewayAddr
  )
{
  EFI_STATUS         Status;
  EFI_IP6_PROTOCOL   *Ip6;
  EFI_IP6_MODE_DATA  Ip6ModeData;
  UINTN              Index;
  EFI_EVENT          TimeOutEvt;
  UINTN              RetryCount;
  BOOLEAN            GatewayIsFound;

  ASSERT (GatewayAddr != NULL);
  ASSERT (Private != NULL);

  Ip6            = Private->Ip6;
  GatewayIsFound = FALSE;
  RetryCount     = 0;
  TimeOutEvt     = NULL;
  Status         = EFI_SUCCESS;
  ZeroMem (GatewayAddr, sizeof (EFI_IPv6_ADDRESS));

  while (TRUE) {
    Status = Ip6->GetModeData (Ip6, &Ip6ModeData, NULL, NULL);
    if (EFI_ERROR (Status)) {
      goto ON_EXIT;
    }

    //
    // Find out the gateway address which can route the message which send to ServerIp.
    //
    for (Index = 0; Index < Ip6ModeData.RouteCount; Index++) {
      if (NetIp6IsNetEqual (&Private->ServerIp.v6, &Ip6ModeData.RouteTable[Index].Destination, Ip6ModeData.RouteTable[Index].PrefixLength)) {
        IP6_COPY_ADDRESS (GatewayAddr, &Ip6ModeData.RouteTable[Index].Gateway);
        GatewayIsFound = TRUE;
        break;
      }
    }

    if (Ip6ModeData.AddressList != NULL) {
      FreePool (Ip6ModeData.AddressList);
    }

    if (Ip6ModeData.GroupTable != NULL) {
      FreePool (Ip6ModeData.GroupTable);
    }

    if (Ip6ModeData.RouteTable != NULL) {
      FreePool (Ip6ModeData.RouteTable);
    }

    if (Ip6ModeData.NeighborCache != NULL) {
      FreePool (Ip6ModeData.NeighborCache);
    }

    if (Ip6ModeData.PrefixTable != NULL) {
      FreePool (Ip6ModeData.PrefixTable);
    }

    if (Ip6ModeData.IcmpTypeList != NULL) {
      FreePool (Ip6ModeData.IcmpTypeList);
    }

    if (GatewayIsFound || (RetryCount == TimeOutInSecond)) {
      break;
    }

    RetryCount++;

    //
    // Delay 1 second then recheck it again.
    //
    if (TimeOutEvt == NULL) {
      Status = gBS->CreateEvent (
                      EVT_TIMER,
                      TPL_CALLBACK,
                      NULL,
                      NULL,
                      &TimeOutEvt
                      );
      if (EFI_ERROR (Status)) {
        goto ON_EXIT;
      }
    }

    Status = gBS->SetTimer (TimeOutEvt, TimerRelative, TICKS_PER_SECOND);
    if (EFI_ERROR (Status)) {
      goto ON_EXIT;
    }

    while (EFI_ERROR (gBS->CheckEvent (TimeOutEvt))) {
      Ip6->Poll (Ip6);
    }
  }

ON_EXIT:
  if (TimeOutEvt != NULL) {
    gBS->CloseEvent (TimeOutEvt);
  }

  if (GatewayIsFound) {
    Status = EFI_SUCCESS;
  } else if (RetryCount == TimeOutInSecond) {
    Status = EFI_TIMEOUT;
  }

  return Status;
}

/**
  Set the IP6 policy to Automatic.

  @param[in]  Private             The pointer to HTTP_BOOT_PRIVATE_DATA.

  @retval     EFI_SUCCESS         Switch the IP policy successfully.
  @retval     Others              Unexpected error happened.

**/
EFI_STATUS
HttpBootSetIp6Policy (
  IN HTTP_BOOT_PRIVATE_DATA  *Private
  )
{
  EFI_IP6_CONFIG_POLICY    Policy;
  EFI_IP6_CONFIG_PROTOCOL  *Ip6Config;
  EFI_STATUS               Status;
  UINTN                    DataSize;

  Ip6Config = Private->Ip6Config;
  DataSize  = sizeof (EFI_IP6_CONFIG_POLICY);

  //
  // Get and store the current policy of IP6 driver.
  //
  Status = Ip6Config->GetData (
                        Ip6Config,
                        Ip6ConfigDataTypePolicy,
                        &DataSize,
                        &Policy
                        );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  if (Policy == Ip6ConfigPolicyManual) {
    Policy = Ip6ConfigPolicyAutomatic;
    Status = Ip6Config->SetData (
                          Ip6Config,
                          Ip6ConfigDataTypePolicy,
                          sizeof (EFI_IP6_CONFIG_POLICY),
                          &Policy
                          );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return EFI_SUCCESS;
}

/**
  This function will register the default DNS addresses to the network device.

  @param[in]  Private             The pointer to HTTP_BOOT_PRIVATE_DATA.
  @param[in]  DataLength          Size of the buffer pointed to by DnsServerData in bytes.
  @param[in]  DnsServerData       Point a list of DNS server address in an array
                                  of EFI_IPv6_ADDRESS instances.

  @retval     EFI_SUCCESS         The DNS configuration has been configured successfully.
  @retval     Others              Failed to configure the address.

**/
EFI_STATUS
HttpBootSetIp6Dns (
  IN HTTP_BOOT_PRIVATE_DATA  *Private,
  IN UINTN                   DataLength,
  IN VOID                    *DnsServerData
  )
{
  EFI_IP6_CONFIG_PROTOCOL  *Ip6Config;

  ASSERT (Private->UsingIpv6);

  Ip6Config = Private->Ip6Config;

  return Ip6Config->SetData (
                      Ip6Config,
                      Ip6ConfigDataTypeDnsServer,
                      DataLength,
                      DnsServerData
                      );
}

/**
  This function will register the IPv6 gateway address to the network device.

  @param[in]  Private             The pointer to HTTP_BOOT_PRIVATE_DATA.

  @retval     EFI_SUCCESS         The new IP configuration has been configured successfully.
  @retval     Others              Failed to configure the address.

**/
EFI_STATUS
HttpBootSetIp6Gateway (
  IN HTTP_BOOT_PRIVATE_DATA  *Private
  )
{
  EFI_IP6_CONFIG_PROTOCOL  *Ip6Config;
  EFI_STATUS               Status;

  ASSERT (Private->UsingIpv6);
  Ip6Config = Private->Ip6Config;

  //
  // Set the default gateway address.
  //
  if (!Private->NoGateway && !NetIp6IsUnspecifiedAddr (&Private->GatewayIp.v6)) {
    Status = Ip6Config->SetData (
                          Ip6Config,
                          Ip6ConfigDataTypeGateway,
                          sizeof (EFI_IPv6_ADDRESS),
                          &Private->GatewayIp.v6
                          );
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  return EFI_SUCCESS;
}

/**
  This function will register the station IP address.

  @param[in]  Private             The pointer to HTTP_BOOT_PRIVATE_DATA.

  @retval     EFI_SUCCESS         The new IP address has been configured successfully.
  @retval     Others              Failed to configure the address.

**/
EFI_STATUS
HttpBootSetIp6Address (
  IN HTTP_BOOT_PRIVATE_DATA  *Private
  )
{
  EFI_STATUS                     Status;
  EFI_IP6_PROTOCOL               *Ip6;
  EFI_IP6_CONFIG_PROTOCOL        *Ip6Cfg;
  EFI_IP6_CONFIG_POLICY          Policy;
  EFI_IP6_CONFIG_MANUAL_ADDRESS  CfgAddr;
  EFI_IPv6_ADDRESS               *Ip6Addr;
  EFI_IPv6_ADDRESS               GatewayAddr;
  EFI_IP6_CONFIG_DATA            Ip6CfgData;
  EFI_EVENT                      MappedEvt;
  UINTN                          DataSize;
  BOOLEAN                        IsAddressOk;
  UINTN                          Index;
  UINT8                          PrefixLength;

  ASSERT (Private->UsingIpv6);

  MappedEvt   = NULL;
  IsAddressOk = FALSE;
  Ip6Addr     = NULL;
  Ip6Cfg      = Private->Ip6Config;
  Ip6         = Private->Ip6;

  ZeroMem (&CfgAddr, sizeof (EFI_IP6_CONFIG_MANUAL_ADDRESS));
  CopyMem (&CfgAddr.Address, &Private->StationIp.v6, sizeof (EFI_IPv6_ADDRESS));
  ZeroMem (&Ip6CfgData, sizeof (EFI_IP6_CONFIG_DATA));

  PrefixLength = 0;
  Status       = HttpBootGetSlaacPrefixLength (Private, &Private->StationIp.v6, &PrefixLength);
  if (!EFI_ERROR (Status) && (PrefixLength != 0)) {
    CfgAddr.PrefixLength = PrefixLength;
    AsciiPrint ("\n  SLAAC: preserving station prefix length /%d for manual IPv6 setup.\n", PrefixLength);
  }

  Ip6CfgData.AcceptIcmpErrors = TRUE;
  Ip6CfgData.DefaultProtocol  = IP6_ICMP;
  Ip6CfgData.HopLimit         = HTTP_BOOT_DEFAULT_HOPLIMIT;
  Ip6CfgData.ReceiveTimeout   = HTTP_BOOT_DEFAULT_LIFETIME;
  Ip6CfgData.TransmitTimeout  = HTTP_BOOT_DEFAULT_LIFETIME;

  Status = Ip6->Configure (Ip6, &Ip6CfgData);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  //
  // Retrieve the gateway address from IP6 route table.
  //
  Status = HttpBootCheckRouteTable (Private, HTTP_BOOT_IP6_ROUTE_TABLE_TIMEOUT, &GatewayAddr);
  if (EFI_ERROR (Status)) {
    Private->NoGateway = TRUE;
  } else {
    IP6_COPY_ADDRESS (&Private->GatewayIp.v6, &GatewayAddr);
  }

  //
  // Set the new address by Ip6ConfigProtocol manually.
  //
  Policy = Ip6ConfigPolicyManual;
  Status = Ip6Cfg->SetData (
                     Ip6Cfg,
                     Ip6ConfigDataTypePolicy,
                     sizeof (EFI_IP6_CONFIG_POLICY),
                     &Policy
                     );
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  //
  // Create a notify event to set address flag when DAD if IP6 driver succeeded.
  //
  Status = gBS->CreateEvent (
                  EVT_NOTIFY_SIGNAL,
                  TPL_NOTIFY,
                  HttpBootCommonNotify,
                  &IsAddressOk,
                  &MappedEvt
                  );
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  //
  // Set static host ip6 address. This is a asynchronous process.
  //
  Status = Ip6Cfg->RegisterDataNotify (
                     Ip6Cfg,
                     Ip6ConfigDataTypeManualAddress,
                     MappedEvt
                     );
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  Status = Ip6Cfg->SetData (
                     Ip6Cfg,
                     Ip6ConfigDataTypeManualAddress,
                     sizeof (EFI_IP6_CONFIG_MANUAL_ADDRESS),
                     &CfgAddr
                     );
  if (EFI_ERROR (Status) && (Status != EFI_NOT_READY)) {
    goto ON_EXIT;
  } else if (Status == EFI_NOT_READY) {
    //
    // Poll the network until the asynchronous process is finished.
    //
    while (!IsAddressOk) {
      Ip6->Poll (Ip6);
    }

    //
    // Check whether the Ip6 Address setting is successed.
    //
    DataSize = 0;
    Status   = Ip6Cfg->GetData (
                         Ip6Cfg,
                         Ip6ConfigDataTypeManualAddress,
                         &DataSize,
                         NULL
                         );
    if ((Status != EFI_BUFFER_TOO_SMALL) || (DataSize == 0)) {
      Status = EFI_DEVICE_ERROR;
      goto ON_EXIT;
    }

    Ip6Addr = AllocatePool (DataSize);
    if (Ip6Addr == NULL) {
      return EFI_OUT_OF_RESOURCES;
    }

    Status = Ip6Cfg->GetData (
                       Ip6Cfg,
                       Ip6ConfigDataTypeManualAddress,
                       &DataSize,
                       (VOID *)Ip6Addr
                       );
    if (EFI_ERROR (Status)) {
      Status = EFI_DEVICE_ERROR;
      goto ON_EXIT;
    }

    for (Index = 0; Index < DataSize / sizeof (EFI_IPv6_ADDRESS); Index++) {
      if (CompareMem (Ip6Addr + Index, &CfgAddr, sizeof (EFI_IPv6_ADDRESS)) == 0) {
        break;
      }
    }

    if (Index == DataSize / sizeof (EFI_IPv6_ADDRESS)) {
      Status = EFI_ABORTED;
      goto ON_EXIT;
    }
  }

ON_EXIT:
  if (MappedEvt != NULL) {
    Ip6Cfg->UnregisterDataNotify (
              Ip6Cfg,
              Ip6ConfigDataTypeManualAddress,
              MappedEvt
              );
    gBS->CloseEvent (MappedEvt);
  }

  if (Ip6Addr != NULL) {
    FreePool (Ip6Addr);
  }

  return Status;
}

/**
  Retry DHCPv6 when EFI_NO_MAPPING is returned, by waiting for Duplicate Address
  Detection (DAD) to complete and restarting the DHCPv6 process.

  This function stops the current DHCP6 session and waits for DAD to complete
  based on the value returned by Ip6Config->GetData(), then retries Dhcp6->Start().

  @param[in]  Dhcp6     The pointer to the EFI_DHCP6_PROTOCOL instance.
  @param[in]  Ip6Cfg    The pointer to the EFI_IP6_CONFIG_PROTOCOL instance.

  @retval EFI_SUCCESS           DHCPv6 process restarted successfully after DAD.
  @retval EFI_DEVICE_ERROR      Failed during DAD timer wait or DHCP restart.
  @retval EFI_OUT_OF_RESOURCES  Failed to allocate timer resources.
  @retval Others                Underlying protocol errors.

**/
EFI_STATUS
HandleDhcp6NoMappingRetry (
  IN EFI_DHCP6_PROTOCOL       *Dhcp6,
  IN EFI_IP6_CONFIG_PROTOCOL  *Ip6Cfg
  )
{
  EFI_STATUS                                Status;
  EFI_STATUS                                TimerStatus;
  EFI_EVENT                                 Timer = NULL;
  UINT64                                    GetMappingTimeOut;
  UINTN                                     DataSize;
  EFI_IP6_CONFIG_DUP_ADDR_DETECT_TRANSMITS  DadXmits;

  //
  // IP6 Linklocal address is not available for use, so stop current Dhcp process
  // and wait for duplicate address detection to finish.
  //
  Dhcp6->Stop (Dhcp6);

  //
  // Get Duplicate Address Detection Transmits count.
  //
  DataSize = sizeof (EFI_IP6_CONFIG_DUP_ADDR_DETECT_TRANSMITS);
  Status   = Ip6Cfg->GetData (
                       Ip6Cfg,
                       Ip6ConfigDataTypeDupAddrDetectTransmits,
                       &DataSize,
                       &DadXmits
                       );
  if (EFI_ERROR (Status)) {
    Dhcp6->Configure (Dhcp6, NULL);
    return Status;
  }

  Status = gBS->CreateEvent (EVT_TIMER, TPL_CALLBACK, NULL, NULL, &Timer);
  if (EFI_ERROR (Status)) {
    Dhcp6->Configure (Dhcp6, NULL);
    return Status;
  }

  GetMappingTimeOut = TICKS_PER_SECOND * DadXmits.DupAddrDetectTransmits + HTTP_BOOT_DAD_ADDITIONAL_DELAY;
  Status            = gBS->SetTimer (Timer, TimerRelative, GetMappingTimeOut);
  if (EFI_ERROR (Status)) {
    gBS->CloseEvent (Timer);
    Dhcp6->Configure (Dhcp6, NULL);
    return Status;
  }

  do {
    TimerStatus = gBS->CheckEvent (Timer);
    if (!EFI_ERROR (TimerStatus)) {
      Status = Dhcp6->Start (Dhcp6);
    }
  } while (TimerStatus == EFI_NOT_READY);

  gBS->CloseEvent (Timer);

  return Status;
}

/**
  Check whether an IPv6 address is usable for SLAAC HTTP boot.

  @param[in]  Ip6Addr       The IPv6 address to check.

  @retval     TRUE          The address is usable.
  @retval     FALSE         The address is not usable.

**/
STATIC
BOOLEAN
HttpBootIsUsableSlaacAddress (
  IN EFI_IPv6_ADDRESS  *Ip6Addr
  )
{
  EFI_IPv6_ADDRESS  Loopback;

  ZeroMem (&Loopback, sizeof (Loopback));
  Loopback.Addr[15] = 1;

  if (NetIp6IsUnspecifiedAddr (Ip6Addr) ||
      NetIp6IsLinkLocalAddr (Ip6Addr)   ||
      !NetIp6IsValidUnicast (Ip6Addr)   ||
      EFI_IP6_EQUAL (Ip6Addr, &Loopback))
  {
    return FALSE;
  }

  return TRUE;
}

/**
  Retrieve the first usable non-link-local IPv6 address on the interface.

  @param[in]  Private       The pointer to HTTP BOOT driver private data.
  @param[out] Ip6Addr       The usable IPv6 address.

  @retval     EFI_SUCCESS   A usable IPv6 address was found.
  @retval     EFI_NOT_FOUND No usable IPv6 address is available.
  @retval     Others        Unexpected error happened.

**/
STATIC
EFI_STATUS
HttpBootGetSlaacAddress (
  IN  HTTP_BOOT_PRIVATE_DATA  *Private,
  OUT EFI_IPv6_ADDRESS        *Ip6Addr,
  OUT UINT8                   *PrefixLength OPTIONAL
  )
{
  EFI_IP6_CONFIG_PROTOCOL        *Ip6Config;
  EFI_IP6_CONFIG_INTERFACE_INFO  *IfInfo;
  EFI_STATUS                     Status;
  UINTN                          DataSize;
  UINTN                          Index;

  Ip6Config = Private->Ip6Config;
  IfInfo    = NULL;
  DataSize  = 0;

  Status = Ip6Config->GetData (
                        Ip6Config,
                        Ip6ConfigDataTypeInterfaceInfo,
                        &DataSize,
                        NULL
                        );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return EFI_NOT_FOUND;
  }

  IfInfo = AllocateZeroPool (DataSize);
  if (IfInfo == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = Ip6Config->GetData (
                        Ip6Config,
                        Ip6ConfigDataTypeInterfaceInfo,
                        &DataSize,
                        IfInfo
                        );
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  Status = EFI_NOT_FOUND;
  for (Index = 0; Index < IfInfo->AddressInfoCount; Index++) {
    if (HttpBootIsUsableSlaacAddress (&IfInfo->AddressInfo[Index].Address)) {
      CopyMem (Ip6Addr, &IfInfo->AddressInfo[Index].Address, sizeof (EFI_IPv6_ADDRESS));
      if (PrefixLength != NULL) {
        *PrefixLength = IfInfo->AddressInfo[Index].PrefixLength;
      }

      Status = EFI_SUCCESS;
      break;
    }
  }

ON_EXIT:
  if (IfInfo != NULL) {
    FreePool (IfInfo);
  }

  return Status;
}

/**
  Retrieve the prefix length for an already discovered SLAAC IPv6 address.

  @param[in]  Private       The pointer to HTTP BOOT driver private data.
  @param[in]  Ip6Addr       The IPv6 address to look up.
  @param[out] PrefixLength  The prefix length associated with Ip6Addr.

  @retval     EFI_SUCCESS   The prefix length was found.
  @retval     EFI_NOT_FOUND The address is not present in interface information.
  @retval     Others        Unexpected error happened.

**/
STATIC
EFI_STATUS
HttpBootGetSlaacPrefixLength (
  IN  HTTP_BOOT_PRIVATE_DATA  *Private,
  IN  EFI_IPv6_ADDRESS        *Ip6Addr,
  OUT UINT8                   *PrefixLength
  )
{
  EFI_IP6_CONFIG_PROTOCOL        *Ip6Config;
  EFI_IP6_CONFIG_INTERFACE_INFO  *IfInfo;
  EFI_STATUS                     Status;
  UINTN                          DataSize;
  UINTN                          Index;

  if ((Ip6Addr == NULL) || (PrefixLength == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  Ip6Config = Private->Ip6Config;
  IfInfo    = NULL;
  DataSize  = 0;

  Status = Ip6Config->GetData (
                        Ip6Config,
                        Ip6ConfigDataTypeInterfaceInfo,
                        &DataSize,
                        NULL
                        );
  if (Status != EFI_BUFFER_TOO_SMALL) {
    return EFI_NOT_FOUND;
  }

  IfInfo = AllocateZeroPool (DataSize);
  if (IfInfo == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Status = Ip6Config->GetData (
                        Ip6Config,
                        Ip6ConfigDataTypeInterfaceInfo,
                        &DataSize,
                        IfInfo
                        );
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  Status = EFI_NOT_FOUND;
  for (Index = 0; Index < IfInfo->AddressInfoCount; Index++) {
    if (EFI_IP6_EQUAL (Ip6Addr, &IfInfo->AddressInfo[Index].Address)) {
      *PrefixLength = IfInfo->AddressInfo[Index].PrefixLength;
      Status        = EFI_SUCCESS;
      break;
    }
  }

ON_EXIT:
  if (IfInfo != NULL) {
    FreePool (IfInfo);
  }

  return Status;
}

/**
  Get the latest Router Advertisement M/O flag information if available.

  @param[in]  Private       The pointer to HTTP BOOT driver private data.
  @param[out] RaInfo        The latest Router Advertisement information.

  @retval     EFI_SUCCESS   Router Advertisement information is returned.
  @retval     EFI_NOT_READY No valid Router Advertisement has been received.
  @retval     Others        Router Advertisement information is unavailable.

**/
STATIC
EFI_STATUS
HttpBootGetLatestRaInfo (
  IN  HTTP_BOOT_PRIVATE_DATA  *Private,
  OUT EDKII_IP6_RA_INFO       *RaInfo
  )
{
  EDKII_IP6_RA_INFO_PROTOCOL  *RaInfoProtocol;
  EFI_STATUS                  Status;

  if ((Private == NULL) || (RaInfo == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  RaInfoProtocol = NULL;
  Status         = gBS->HandleProtocol (
                          Private->Controller,
                          &gEdkiiIp6RaInfoProtocolGuid,
                          (VOID **)&RaInfoProtocol
                          );
  if (EFI_ERROR (Status) || (RaInfoProtocol == NULL)) {
    return EFI_ERROR (Status) ? Status : EFI_NOT_FOUND;
  }

  return RaInfoProtocol->GetLatestRaInfo (RaInfoProtocol, RaInfo);
}

/**
  Print the latest Router Advertisement M/O flag information if available.

  @param[in]  Private       The pointer to HTTP BOOT driver private data.

**/
STATIC
VOID
HttpBootPrintLatestRaInfo (
  IN HTTP_BOOT_PRIVATE_DATA  *Private
  )
{
  EDKII_IP6_RA_INFO  RaInfo;
  EFI_STATUS         Status;

  Status = HttpBootGetLatestRaInfo (Private, &RaInfo);
  if (Status == EFI_NOT_READY) {
    AsciiPrint ("  RA: not received.\n");
    return;
  }

  if (EFI_ERROR (Status)) {
    AsciiPrint ("  RA: unavailable: %r.\n", Status);
    return;
  }

  AsciiPrint (
    "  RA: M=%d, O=%d\n",
    RaInfo.ManagedFlag ? 1 : 0,
    RaInfo.OtherConfigFlag ? 1 : 0
    );
}

/**
  Wait for a usable SLAAC address already configured on the interface.

  @param[in]  Private       The pointer to HTTP BOOT driver private data.
  @param[out] StationIp     The usable SLAAC station IPv6 address.

  @retval     EFI_SUCCESS   SLAAC HTTP boot conditions are met.
  @retval     Others        SLAAC path is not applicable.

**/
STATIC
EFI_STATUS
HttpBootDhcp6DiscoverSlaac (
  IN  HTTP_BOOT_PRIVATE_DATA  *Private,
  OUT EFI_IPv6_ADDRESS        *StationIp
  )
{
  EDKII_IP6_RA_INFO                 RaInfo;
  EFI_STATUS                        Status;
  HTTP_BOOT_DHCP6_SLAAC_DECISION    Decision;
  UINTN                             RetryCount;
  UINT8                             PrefixLength;

  RetryCount   = 0;
  PrefixLength = 0;
  Decision     = HttpBootDhcp6SlaacDecisionWait;
  ZeroMem (StationIp, sizeof (EFI_IPv6_ADDRESS));

  AsciiPrint ("\n  SLAAC: waiting for RA M=0/O=1 and configured non-link-local address.\n");

  while (RetryCount < HTTP_BOOT_DHCP6_SLAAC_DISCOVER_TIMEOUT * 10) {
    if ((RetryCount % 10) == 0) {
      AsciiPrint (
        "\n  SLAAC: wait loop %d/%d, checking RA and configured addresses.\n",
        RetryCount / 10,
        HTTP_BOOT_DHCP6_SLAAC_DISCOVER_TIMEOUT
        );
      HttpBootPrintLatestRaInfo (Private);
    }

    if (Decision == HttpBootDhcp6SlaacDecisionWait) {
      Status = HttpBootGetLatestRaInfo (Private, &RaInfo);
      if (Status == EFI_NOT_READY) {
        gBS->Stall (100 * 1000);
        RetryCount++;
        continue;
      }

      if (EFI_ERROR (Status)) {
        AsciiPrint ("\n  SLAAC: RA information unavailable: %r.\n", Status);
        return Status;
      }

      if (RaInfo.ManagedFlag) {
        AsciiPrint ("\n  SLAAC: RA M=1, falling back to DHCPv6 SARR.\n");
        return EFI_UNSUPPORTED;
      }

      if (!RaInfo.OtherConfigFlag) {
        AsciiPrint ("\n  SLAAC: RA O=0, falling back to DHCPv6 SARR.\n");
        return EFI_UNSUPPORTED;
      }

      Decision = HttpBootDhcp6SlaacDecisionTryInfoRequest;
    }

    Status = HttpBootGetSlaacAddress (Private, StationIp, &PrefixLength);
    if (!EFI_ERROR (Status)) {
      AsciiPrint ("\n  SLAAC: station address ready from IPv6 configuration: ");
      HttpBootShowIp6Addr (StationIp);
      AsciiPrint ("/%d.\n", PrefixLength);
      return EFI_SUCCESS;
    }

    if (Status != EFI_NOT_FOUND) {
      AsciiPrint ("\n  SLAAC: failed to check station address: %r.\n", Status);
      return Status;
    }

    gBS->Stall (100 * 1000);
    RetryCount++;
  }

  if (Decision == HttpBootDhcp6SlaacDecisionWait) {
    AsciiPrint ("\n  SLAAC: timeout waiting for Router Advertisement.\n");
  } else {
    AsciiPrint ("\n  SLAAC: timeout waiting for usable address.\n");
  }

  return EFI_TIMEOUT;
}

/**
  DHCPv6 Information Request reply callback for SLAAC HTTP boot.

  @param[in]  This              The pointer to the EFI DHCPv6 Protocol.
  @param[in]  Context           Pointer to the callback context.
  @param[in]  Packet            The received Reply packet.

  @retval EFI_SUCCESS           Accept the reply and finish Information Request.
  @retval EFI_NOT_READY         Ignore this reply and keep waiting.
  @retval EFI_OUT_OF_RESOURCES  There are not enough resources.

**/
STATIC
EFI_STATUS
EFIAPI
HttpBootDhcp6InfoRequestCallback (
  IN EFI_DHCP6_PROTOCOL  *This,
  IN VOID                *Context,
  IN EFI_DHCP6_PACKET    *Packet
  )
{
  HTTP_BOOT_DHCP6_INFO_REQUEST_CONTEXT  *RequestContext;
  HTTP_BOOT_PRIVATE_DATA                *Private;
  HTTP_BOOT_DHCP6_PACKET_CACHE          *Cache6;
  EFI_STATUS                            Status;
  HTTP_BOOT_OFFER_TYPE                  OfferType;

  (VOID)This;

  if ((Context == NULL) || (Packet == NULL) || (Packet->Dhcp6.Header.MessageType != Dhcp6MsgReply)) {
    return EFI_NOT_READY;
  }

  RequestContext = (HTTP_BOOT_DHCP6_INFO_REQUEST_CONTEXT *)Context;
  Private        = RequestContext->Private;
  Cache6         = &Private->OfferBuffer[0].Dhcp6;

  HttpBootDhcp6ClearOfferState (Private);
  Cache6->Packet.Offer.Size = HTTP_CACHED_DHCP6_PACKET_MAX_SIZE;

  Status = HttpBootCacheDhcp6InfoReply (
             &Cache6->Packet.Offer,
             Packet,
             (BOOLEAN)(Private->FilePathUri == NULL)
             );
  if (EFI_ERROR (Status)) {
    return EFI_NOT_READY;
  }

  Status = HttpBootParseDhcp6Packet (
             Cache6,
             (BOOLEAN)(Private->FilePathUri != NULL)
             );
  if (EFI_ERROR (Status)) {
    if (Cache6->UriParser != NULL) {
      HttpUrlFreeParser (Cache6->UriParser);
      Cache6->UriParser = NULL;
    }

    return (Status == EFI_OUT_OF_RESOURCES) ? Status : EFI_NOT_READY;
  }

  OfferType = Cache6->OfferType;
  if (OfferType == HttpOfferTypeProxyIpUri) {
    OfferType = (Cache6->OptList[HTTP_BOOT_DHCP6_IDX_DNS_SERVER] != NULL) ? HttpOfferTypeDhcpIpUriDns : HttpOfferTypeDhcpIpUri;
  } else if (OfferType == HttpOfferTypeProxyNameUri) {
    OfferType = (Cache6->OptList[HTTP_BOOT_DHCP6_IDX_DNS_SERVER] != NULL) ? HttpOfferTypeDhcpNameUriDns : HttpOfferTypeDhcpNameUri;
  } else if ((Private->FilePathUri != NULL) &&
             (OfferType != HttpOfferTypeDhcpDns) &&
             (OfferType != HttpOfferTypeDhcpIpUriDns) &&
             (OfferType != HttpOfferTypeDhcpNameUriDns) &&
             (OfferType != HttpOfferTypeDhcpOnly) &&
             (OfferType != HttpOfferTypeDhcpIpUri))
  {
    if (Cache6->UriParser != NULL) {
      HttpUrlFreeParser (Cache6->UriParser);
      Cache6->UriParser = NULL;
    }

    return EFI_NOT_READY;
  } else if ((Private->FilePathUri == NULL) &&
             (OfferType != HttpOfferTypeDhcpIpUri) &&
             (OfferType != HttpOfferTypeDhcpIpUriDns) &&
             (OfferType != HttpOfferTypeDhcpNameUriDns))
  {
    if (Cache6->UriParser != NULL) {
      HttpUrlFreeParser (Cache6->UriParser);
      Cache6->UriParser = NULL;
    }

    return EFI_NOT_READY;
  }

  Cache6->OfferType = OfferType;
  ASSERT (OfferType < HttpOfferTypeMax);

  Private->OfferNum                  = 1;
  Private->OfferCount[OfferType]     = 1;
  Private->OfferIndex[OfferType][0]  = 0;
  RequestContext->Accepted           = TRUE;

  return EFI_SUCCESS;
}

/**
  Try IPv6 HTTP Boot with SLAAC address assignment and DHCPv6 Information Request.

  @param[in]  Private           Pointer to HTTP_BOOT private data.

  @retval EFI_SUCCESS           The SLAAC Information Request path succeeded.
  @retval Others                The caller may fall back to SARR.

**/
STATIC
EFI_STATUS
HttpBootDhcp6TrySlaacInfoRequest (
  IN HTTP_BOOT_PRIVATE_DATA  *Private
  )
{
  EFI_DHCP6_PROTOCOL                    *Dhcp6;
  EFI_DHCP6_RETRANSMISSION              Retransmit;
  EFI_DHCP6_PACKET_OPTION               *OptList[HTTP_BOOT_DHCP6_OPTION_MAX_NUM];
  HTTP_BOOT_DHCP6_INFO_REQUEST_CONTEXT  RequestContext;
  HTTP_BOOT_DHCP6_PACKET_CACHE          *Cache6;
  EFI_DHCP6_PACKET_OPTION               *BootFileUrl;
  UINT32                                OptCount;
  UINT8                                 Buffer[HTTP_BOOT_DHCP6_OPTION_MAX_SIZE];
  EFI_STATUS                            Status;

  Dhcp6 = Private->Dhcp6;
  ASSERT (Dhcp6 != NULL);

  Status = HttpBootDhcp6DiscoverSlaac (Private, &Private->StationIp.v6);
  if (EFI_ERROR (Status)) {
    ZeroMem (&Private->StationIp.v6, sizeof (EFI_IPv6_ADDRESS));
    HttpBootDhcp6ClearOfferState (Private);
    Dhcp6->Configure (Dhcp6, NULL);
    return Status;
  }

  HttpBootDhcp6ClearOfferState (Private);

  OptCount = HttpBootBuildDhcp6Options (Private, OptList, Buffer);
  ASSERT (OptCount > 1);

  ZeroMem (&Retransmit, sizeof (Retransmit));
  Retransmit.Irt = 4;
  Retransmit.Mrc = 2;
  Retransmit.Mrt = 4;
  Retransmit.Mrd = HTTP_BOOT_DHCP6_INFO_REQ_TIMEOUT;

  ZeroMem (&RequestContext, sizeof (RequestContext));
  RequestContext.Private = Private;

  Status = Dhcp6->InfoRequest (
                    Dhcp6,
                    TRUE,
                    OptList[0],
                    OptCount - 1,
                    &OptList[1],
                    &Retransmit,
                    NULL,
                    HttpBootDhcp6InfoRequestCallback,
                    &RequestContext
                    );
  if (EFI_ERROR (Status) || !RequestContext.Accepted) {
    AsciiPrint ("\n  SLAAC: DHCPv6 Information Request did not return HTTP boot information: %r.\n", Status);
    Status = EFI_DEVICE_ERROR;
    goto ON_ERROR;
  }

  HttpBootSelectDhcpOffer (Private);
  if (Private->SelectIndex == 0) {
    AsciiPrint ("\n  SLAAC: no usable HTTP boot offer after Information Request.\n");
    Status = EFI_NOT_FOUND;
    goto ON_ERROR;
  }

  Cache6      = &Private->OfferBuffer[Private->SelectIndex - 1].Dhcp6;
  BootFileUrl = Cache6->OptList[HTTP_BOOT_DHCP6_IDX_BOOT_FILE_URL];
  if (Private->FilePathUri == NULL) {
    if (BootFileUrl == NULL) {
      AsciiPrint ("\n  SLAAC: selected offer does not include BootFile URL.\n");
      Status = EFI_NOT_FOUND;
      goto ON_ERROR;
    }

    Status = HttpBootCheckUriScheme ((CHAR8 *)BootFileUrl->Data);
  } else {
    Status = HttpBootCheckUriScheme (Private->FilePathUri);
  }

  if (EFI_ERROR (Status)) {
    AsciiPrint ("\n  SLAAC: Boot URI scheme check failed: %r.\n", Status);
    goto ON_ERROR;
  }

  AsciiPrint ("\n  Station IPv6 address is ");
  HttpBootShowIp6Addr (&Private->StationIp.v6);
  AsciiPrint ("\n");

  return EFI_SUCCESS;

ON_ERROR:
  HttpBootDhcp6ClearOfferState (Private);
  ZeroMem (&Private->StationIp.v6, sizeof (EFI_IPv6_ADDRESS));

  Dhcp6->Configure (Dhcp6, NULL);
  return Status;
}

/**
  Start the S.A.R.R DHCPv6 process to acquire the IPv6 address and other Http boot information.

  @param[in]  Private           Pointer to HTTP_BOOT private data.

  @retval EFI_SUCCESS           The S.A.R.R process successfully finished.
  @retval Others                Failed to finish the S.A.R.R process.

**/
EFI_STATUS
HttpBootDhcp6Sarr (
  IN HTTP_BOOT_PRIVATE_DATA  *Private
  )
{
  EFI_DHCP6_PROTOCOL        *Dhcp6;
  EFI_DHCP6_CONFIG_DATA     Config;
  EFI_DHCP6_MODE_DATA       Mode;
  EFI_DHCP6_RETRANSMISSION  *Retransmit;
  EFI_DHCP6_PACKET_OPTION   *OptList[HTTP_BOOT_DHCP6_OPTION_MAX_NUM];
  UINT32                    OptCount;
  UINT8                     Buffer[HTTP_BOOT_DHCP6_OPTION_MAX_SIZE];
  EFI_STATUS                Status;
  UINT32                    Random;
  EFI_IP6_CONFIG_PROTOCOL   *Ip6Cfg;

  Dhcp6 = Private->Dhcp6;
  ASSERT (Dhcp6 != NULL);

  ASSERT (Private->UsingIpv6);
  Ip6Cfg = Private->Ip6Config;

  Status = HttpBootDhcp6TrySlaacInfoRequest (Private);
  if (!EFI_ERROR (Status)) {
    return EFI_SUCCESS;
  }

  //
  // Build options list for the request packet.
  //
  OptCount = HttpBootBuildDhcp6Options (Private, OptList, Buffer);
  ASSERT (OptCount > 0);

  Status = PseudoRandomU32 (&Random);
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a failed to generate random number: %r\n", __func__, Status));
    return Status;
  }

  Retransmit = AllocateZeroPool (sizeof (EFI_DHCP6_RETRANSMISSION));
  if (Retransmit == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem (&Mode, sizeof (EFI_DHCP6_MODE_DATA));
  ZeroMem (&Config, sizeof (EFI_DHCP6_CONFIG_DATA));

  Config.OptionCount           = OptCount;
  Config.OptionList            = OptList;
  Config.Dhcp6Callback         = HttpBootDhcp6CallBack;
  Config.CallbackContext       = Private;
  Config.IaInfoEvent           = NULL;
  Config.RapidCommit           = FALSE;
  Config.ReconfigureAccept     = FALSE;
  Config.IaDescriptor.IaId     = Random;
  Config.IaDescriptor.Type     = EFI_DHCP6_IA_TYPE_NA;
  Config.SolicitRetransmission = Retransmit;
  Retransmit->Irt              = 4;
  Retransmit->Mrc              = 4;
  Retransmit->Mrt              = 32;
  Retransmit->Mrd              = 60;

  //
  // Configure the DHCPv6 instance for HTTP boot.
  //
  Status = Dhcp6->Configure (Dhcp6, &Config);
  FreePool (Retransmit);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  //
  // Initialize the record fields for DHCPv6 offer in private data.
  //
  Private->OfferNum    = 0;
  Private->SelectIndex = 0;
  ZeroMem (Private->OfferCount, sizeof (Private->OfferCount));
  ZeroMem (Private->OfferIndex, sizeof (Private->OfferIndex));

  //
  // Start DHCPv6 S.A.R.R. process to acquire IPv6 address.
  //
  Status = Dhcp6->Start (Dhcp6);
  if (Status == EFI_NO_MAPPING) {
    Status = HandleDhcp6NoMappingRetry (Dhcp6, Ip6Cfg);
  }

  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  //
  // Get the acquired IPv6 address and store them.
  //
  Status = Dhcp6->GetModeData (Dhcp6, &Mode, NULL);
  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }

  ASSERT (Mode.Ia->State == Dhcp6Bound);
  CopyMem (&Private->StationIp.v6, &Mode.Ia->IaAddress[0].IpAddress, sizeof (EFI_IPv6_ADDRESS));

  AsciiPrint ("\n  Station IPv6 address is ");
  HttpBootShowIp6Addr (&Private->StationIp.v6);
  AsciiPrint ("\n");

ON_EXIT:
  if (EFI_ERROR (Status)) {
    Dhcp6->Stop (Dhcp6);
    Dhcp6->Configure (Dhcp6, NULL);
  } else {
    ZeroMem (&Config, sizeof (EFI_DHCP6_CONFIG_DATA));
    Dhcp6->Configure (Dhcp6, &Config);
    if (Mode.ClientId != NULL) {
      FreePool (Mode.ClientId);
    }

    if (Mode.Ia != NULL) {
      FreePool (Mode.Ia);
    }
  }

  return Status;
}
