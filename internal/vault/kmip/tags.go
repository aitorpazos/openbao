// Copyright (c) OpenBao Contributors
// SPDX-License-Identifier: MPL-2.0

package kmip

// Tags from OASIS KMIP 1.4 section 9.1.3.1.
// Additional tags: KMIP 2.0 section 11.54; legacy templates: 1.4 section 9.1.3.1.
const (
	Attributes                    uint32 = 0x420125
	CommonAttributes              uint32 = 0x420126
	PrivateKeyAttributes          uint32 = 0x420127
	PublicKeyAttributes           uint32 = 0x420128
	AttributeReference            uint32 = 0x42013b
	DefaultsInformation           uint32 = 0x420152
	ObjectDefaults                uint32 = 0x420153
	ProtectionStorageMasks        uint32 = 0x42015f
	CertificateType               uint32 = 0x42001d
	CertificateValue              uint32 = 0x42001e
	CertificateLength             uint32 = 0x4200ad
	CommonTemplateAttribute       uint32 = 0x42001f
	PrivateKeyTemplateAttribute   uint32 = 0x420065
	PublicKeyTemplateAttribute    uint32 = 0x42006e
	CryptographicDomainParameters uint32 = 0x420029
	RecommendedCurve              uint32 = 0x420075
	Link                          uint32 = 0x42004a
	LinkType                      uint32 = 0x42004b
	LinkedObjectIdentifier        uint32 = 0x42004c
	OpRegister                    uint32 = 0x03
	AsynchronousIndicator         uint32 = 0x420007
	BatchErrorContinuationOption  uint32 = 0x42000e
	BatchOrderOption              uint32 = 0x420010
	BlockCipherMode               uint32 = 0x420011
	EncryptionKeyInformation      uint32 = 0x420036
	KeyWrappingData               uint32 = 0x420046
	KeyWrappingSpecification      uint32 = 0x420047
	MaximumResponseSize           uint32 = 0x420050
	WrappingMethod                uint32 = 0x42009e
	EncodingOption                uint32 = 0x4200a3
	ActivationDate                uint32 = 0x420001
	ArchiveDate                   uint32 = 0x420005
	Attribute                     uint32 = 0x420008
	AttributeName                 uint32 = 0x42000a
	AttributeValue                uint32 = 0x42000b
	BatchCount                    uint32 = 0x42000d
	BatchItem                     uint32 = 0x42000f
	Certificate                   uint32 = 0x420013
	CryptographicAlgorithm        uint32 = 0x420028
	CryptographicLength           uint32 = 0x42002a
	CryptographicParameters       uint32 = 0x42002b
	CryptographicUsageMask        uint32 = 0x42002c
	KeyBlock                      uint32 = 0x420040
	KeyFormatType                 uint32 = 0x420042
	KeyMaterial                   uint32 = 0x420043
	KeyValue                      uint32 = 0x420045
	ObjectType                    uint32 = 0x420057
	OpaqueDataType                uint32 = 0x420059
	OpaqueDataValue               uint32 = 0x42005a
	OpaqueObject                  uint32 = 0x42005b
	Operation                     uint32 = 0x42005c
	PrivateKey                    uint32 = 0x420064
	PrivateKeyUniqueIdentifier    uint32 = 0x420066
	ProtocolVersion               uint32 = 0x420069
	ProtocolVersionMajor          uint32 = 0x42006a
	ProtocolVersionMinor          uint32 = 0x42006b
	PublicKey                     uint32 = 0x42006d
	PublicKeyUniqueIdentifier     uint32 = 0x42006f
	QueryFunction                 uint32 = 0x420074
	RequestHeader                 uint32 = 0x420077
	RequestMessage                uint32 = 0x420078
	RequestPayload                uint32 = 0x420079
	ResponseHeader                uint32 = 0x42007a
	ResponseMessage               uint32 = 0x42007b
	ResponsePayload               uint32 = 0x42007c
	ResultMessage                 uint32 = 0x42007d
	ResultReason                  uint32 = 0x42007e
	ResultStatus                  uint32 = 0x42007f
	SecretData                    uint32 = 0x420085
	State                         uint32 = 0x42008d
	SymmetricKey                  uint32 = 0x42008f
	TemplateAttribute             uint32 = 0x420091
	TimeStamp                     uint32 = 0x420092
	UniqueBatchItemID             uint32 = 0x420093
	UniqueIdentifier              uint32 = 0x420094
	VendorIdentification          uint32 = 0x42009d
	Data                          uint32 = 0x4200c2
	SignatureData                 uint32 = 0x4200c3
)
const (
	OpCreate           uint32 = 0x01
	OpCreateKeyPair    uint32 = 0x02
	OpRekey            uint32 = 0x04
	OpLocate           uint32 = 0x08
	OpGet              uint32 = 0x0a
	OpGetAttributes    uint32 = 0x0b
	OpGetAttributeList uint32 = 0x0c
	OpActivate         uint32 = 0x12
	OpDestroy          uint32 = 0x14
	OpQuery            uint32 = 0x18
	OpDiscoverVersions uint32 = 0x1e
	OpSign             uint32 = 0x21
)

var Operations = map[uint32]string{OpRegister: "register", OpCreateKeyPair: "create_keypair", OpSign: "sign", OpCreate: "create", OpRekey: "rekey", OpLocate: "locate", OpGet: "get", OpGetAttributes: "get_attributes", OpGetAttributeList: "get_attribute_list", OpActivate: "activate", OpDestroy: "destroy", OpQuery: "query", OpDiscoverVersions: "discover_versions"}
var Tags = map[string]uint32{"Link": Link, "Certificate Type": CertificateType, "Certificate Length": CertificateLength, "Cryptographic Domain Parameters": CryptographicDomainParameters, "Cryptographic Parameters": CryptographicParameters, "Object Type": ObjectType, "Unique Identifier": UniqueIdentifier, "Cryptographic Algorithm": CryptographicAlgorithm, "Cryptographic Length": CryptographicLength, "Cryptographic Usage Mask": CryptographicUsageMask, "State": State, "Activation Date": ActivationDate, "Private Key Unique Identifier": PrivateKeyUniqueIdentifier, "Public Key Unique Identifier": PublicKeyUniqueIdentifier, "Archive Date": ArchiveDate}
