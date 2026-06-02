package sudosocpb

/*
	SUDOSOC-C2 Framework
	Copyright (C) 2026  sudosoc — Seif

	Android protobuf message stubs.
	These types are manually defined until `make pb` regenerates them from
	sudosoc.proto. They implement proto.Message to work with the existing RPC layer.
*/

import (
	"github.com/sudosoc/SUDOSOC-C2/protobuf/commonpb"
	"google.golang.org/protobuf/runtime/protoimpl"
)

// ════════════════════════════════════════════════════════════════════
// AndroidDeviceInfo
// ════════════════════════════════════════════════════════════════════

type AndroidDeviceInfoReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Request *commonpb.Request `protobuf:"bytes,9,opt,name=Request,proto3" json:"Request,omitempty"`
}

func (x *AndroidDeviceInfoReq) Reset()         {}
func (x *AndroidDeviceInfoReq) String() string  { return "AndroidDeviceInfoReq" }
func (x *AndroidDeviceInfoReq) ProtoMessage()   {}

type AndroidDeviceInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Manufacturer string            `protobuf:"bytes,1,opt,name=Manufacturer,proto3" json:"Manufacturer,omitempty"`
	Model        string            `protobuf:"bytes,2,opt,name=Model,proto3" json:"Model,omitempty"`
	AndroidVer   string            `protobuf:"bytes,3,opt,name=AndroidVer,proto3" json:"AndroidVer,omitempty"`
	SdkVersion   string            `protobuf:"bytes,4,opt,name=SdkVersion,proto3" json:"SdkVersion,omitempty"`
	Hostname     string            `protobuf:"bytes,5,opt,name=Hostname,proto3" json:"Hostname,omitempty"`
	Username     string            `protobuf:"bytes,6,opt,name=Username,proto3" json:"Username,omitempty"`
	Arch         string            `protobuf:"bytes,7,opt,name=Arch,proto3" json:"Arch,omitempty"`
	IsRooted     bool              `protobuf:"varint,8,opt,name=IsRooted,proto3" json:"IsRooted,omitempty"`
	BuildId      string            `protobuf:"bytes,10,opt,name=BuildId,proto3" json:"BuildId,omitempty"`
	Fingerprint  string            `protobuf:"bytes,11,opt,name=Fingerprint,proto3" json:"Fingerprint,omitempty"`
	SerialNumber string            `protobuf:"bytes,12,opt,name=SerialNumber,proto3" json:"SerialNumber,omitempty"`
	Response     *commonpb.Response `protobuf:"bytes,9,opt,name=Response,proto3" json:"Response,omitempty"`
}

func (x *AndroidDeviceInfo) Reset()        {}
func (x *AndroidDeviceInfo) String() string { return x.Model }
func (x *AndroidDeviceInfo) ProtoMessage()  {}

// ════════════════════════════════════════════════════════════════════
// AndroidApps
// ════════════════════════════════════════════════════════════════════

type AndroidAppsReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Request *commonpb.Request `protobuf:"bytes,9,opt,name=Request,proto3" json:"Request,omitempty"`
}

func (x *AndroidAppsReq) Reset()        {}
func (x *AndroidAppsReq) String() string { return "AndroidAppsReq" }
func (x *AndroidAppsReq) ProtoMessage()  {}

type AndroidApp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	PackageName string `protobuf:"bytes,1,opt,name=PackageName,proto3" json:"PackageName,omitempty"`
	ApkPath     string `protobuf:"bytes,2,opt,name=ApkPath,proto3" json:"ApkPath,omitempty"`
}

func (x *AndroidApp) Reset()        {}
func (x *AndroidApp) String() string { return x.PackageName }
func (x *AndroidApp) ProtoMessage()  {}

type AndroidApps struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Apps     []*AndroidApp      `protobuf:"bytes,1,rep,name=Apps,proto3" json:"Apps,omitempty"`
	Response *commonpb.Response `protobuf:"bytes,9,opt,name=Response,proto3" json:"Response,omitempty"`
}

func (x *AndroidApps) Reset()        {}
func (x *AndroidApps) String() string { return "AndroidApps" }
func (x *AndroidApps) ProtoMessage()  {}

// ════════════════════════════════════════════════════════════════════
// AndroidGeneric (SMS, Contacts, Location, WiFi, Storage, Battery)
// ════════════════════════════════════════════════════════════════════

type AndroidGenericReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	MsgType uint32            `protobuf:"varint,1,opt,name=MsgType,proto3" json:"MsgType,omitempty"`
	Request *commonpb.Request `protobuf:"bytes,9,opt,name=Request,proto3" json:"Request,omitempty"`
}

func (x *AndroidGenericReq) Reset()        {}
func (x *AndroidGenericReq) String() string { return "AndroidGenericReq" }
func (x *AndroidGenericReq) ProtoMessage()  {}

type AndroidGenericResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Data     string             `protobuf:"bytes,1,opt,name=Data,proto3" json:"Data,omitempty"`
	Response *commonpb.Response `protobuf:"bytes,9,opt,name=Response,proto3" json:"Response,omitempty"`
}

func (x *AndroidGenericResp) Reset()        {}
func (x *AndroidGenericResp) String() string { return x.Data }
func (x *AndroidGenericResp) ProtoMessage()  {}

// ════════════════════════════════════════════════════════════════════
// AndroidRootShell
// ════════════════════════════════════════════════════════════════════

type AndroidRootShellReq struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Command string            `protobuf:"bytes,1,opt,name=Command,proto3" json:"Command,omitempty"`
	Request *commonpb.Request `protobuf:"bytes,9,opt,name=Request,proto3" json:"Request,omitempty"`
}

func (x *AndroidRootShellReq) Reset()        {}
func (x *AndroidRootShellReq) String() string { return x.Command }
func (x *AndroidRootShellReq) ProtoMessage()  {}

type AndroidRootShellResp struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Output   string             `protobuf:"bytes,1,opt,name=Output,proto3" json:"Output,omitempty"`
	Status   int32              `protobuf:"varint,2,opt,name=Status,proto3" json:"Status,omitempty"`
	Response *commonpb.Response `protobuf:"bytes,9,opt,name=Response,proto3" json:"Response,omitempty"`
}

func (x *AndroidRootShellResp) Reset()        {}
func (x *AndroidRootShellResp) String() string { return x.Output }
func (x *AndroidRootShellResp) ProtoMessage()  {}
