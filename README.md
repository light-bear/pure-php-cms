# Pure PHP ASN.1 CMS

> [!CAUTION]
> **此项目为 AI 重制版，尚未经完整、独立的安全审计和跨平台互操作验证，请谨慎使用。**
> 不建议直接用于生产环境、金融交易、证书信任判断或其他高安全等级场景。使用者应自行完成
> 代码审计、算法合规检查、边界测试，并与目标系统进行充分的互操作验证。

这是独立于上级项目的 PHP 7.4+ RFC 3852 CMS 实现。ASN.1 BER/DER、CMS
结构和格式转换由 PHP 实现；RSA、ECDH、AES、HMAC 等基础密码运算仍使用 PHP
OpenSSL 扩展，不依赖 PHP 8 才提供的 `openssl_cms_*`。

本实现主要用于研究 CMS 数据结构、兼容 PHP 7 环境，以及处理无法调用
`openssl_cms_*` 的场景。它不是 OpenSSL CMS 工具或成熟密码库的等价替代品。

> [!IMPORTANT]
> PHP 8 的 OpenSSL 标准扩展已经提供 `openssl_cms_sign()`、`openssl_cms_verify()`、
> `openssl_cms_encrypt()`、`openssl_cms_decrypt()`、`openssl_cms_read()` 和
> `openssl_cms_export()` 等 `openssl_cms_*` 方法。如果运行环境允许使用这些标准库
> API，建议优先基于标准库实现 CMS 功能，并结合目标系统完成互操作测试。标准库方案通常
> 能获得更成熟的底层 OpenSSL 实现、维护和安全更新支持。

选择本项目通常只适用于必须兼容 PHP 7、需要直接研究或控制 ASN.1/CMS 结构，或者标准库
接口无法覆盖特定数据格式的情况。即使采用 PHP 8 标准库，证书信任链、吊销状态、业务授权、
原文规范化和重放防护仍需由应用层正确实现。

## 环境要求

- PHP 7.4 或更高版本。
- PHP OpenSSL 扩展。
- Composer，用于 PSR-4 自动加载和运行测试。
- 运行环境必须提供可用的随机数源和受支持的 OpenSSL 算法。

安装依赖：

```shell
composer install
```

## 已实现范围

### ASN.1

- DER 编码。
- BER definite-length 和 indefinite-length 解码。
- SEQUENCE、SET、INTEGER、OBJECT IDENTIFIER、OCTET STRING、BIT STRING、NULL、
  UTCTime 及上下文标签等 CMS 所需类型。
- constructed OCTET STRING 拼接。
- 嵌套深度、节点数量和长度边界检查。
- DER SET 排序。

### CMS 内容类型

- Data。
- SignedData。
- EnvelopedData。
- DigestedData，支持封装内容和分离内容。
- EncryptedData。
- AuthenticatedData，支持封装内容和分离内容。

### SignedData

- 封装签名和分离签名。
- 一个或多个签名者。
- SHA-1 和 SHA-256 摘要。
- RSA PKCS#1 v1.5 签名。
- issuerAndSerialNumber 和 subjectKeyIdentifier 签名者标识。
- `content-type`、`message-digest` 和 `signing-time` 签名属性。
- countersignature 计数签名。
- 从 CMS 内嵌证书或调用方提供的候选证书中定位签名证书。
- 二进制原文和签名篡改检测。

SHA-1 仅用于验证和兼容旧系统数据。创建新签名时应使用 SHA-256 或经过业务安全规范
批准的更强算法。

### EnvelopedData

覆盖 RFC 3852 `RecipientInfo` 的五种分支：

- KeyTransRecipientInfo：RSA PKCS#1 v1.5 密钥传输，支持多个接收者。
- KeyAgreeRecipientInfo：P-256 ECDH、X9.63 SHA-256 KDF 和 AES-256 Key Wrap。
- KEKRecipientInfo：AES Key Wrap。
- PasswordRecipientInfo：PBKDF2-HMAC-SHA256 和 AES-256 Key Wrap。
- OtherRecipientInfo：通过回调交给业务代码扩展。

内容加密当前支持 AES-128-CBC 和 AES-256-CBC。

### AuthenticatedData

- HMAC-SHA256。
- KEKRecipientInfo。
- 封装内容和分离内容。
- MAC 篡改检测。

### 数据格式

- 二进制 DER。
- PEM。
- opaque S/MIME `application/pkcs7-mime`。

## 已知限制与安全边界

以下内容不应由 CMS 语法验签结果代替：

- 不建立或验证 X.509 证书信任链。
- 不检查证书有效期、用途、吊销状态、CRL 或 OCSP。
- 不执行业务身份、商户、银行或证书主体授权判断。
- 不提供私钥存储、密码机、HSM 或密钥生命周期管理。
- 不保证与所有 OpenSSL、Java、Windows CryptoAPI 或厂商 CMS 实现完全互操作。
- PHP 8 环境如无特殊兼容要求，应优先评估标准库 `openssl_cms_*`，而不是自行维护本实现。
- 当前没有覆盖 RFC 3852 允许的所有算法组合、证书选择、CRL、originatorInfo 和
  任意扩展属性。
- opaque S/MIME 仅处理 CMS MIME 实体，不实现完整邮件客户端所需的 multipart/signed、
  邮件规范化和 MIME 树处理。
- 解密失败或 MAC/签名验证失败只表示当前输入不满足验证条件，不应向外部调用者暴露
  过细的密码学失败差异。

因此，“验签成功”仅表示签名值、摘要和已解析 CMS 属性在当前输入下匹配。调用方仍须
独立完成证书信任、授权策略、时间有效性、重放防护和业务字段校验。

## 代码结构

- `src/SignedData.php`：SignedData 的签名、验签和 PEM 转换门面。
- `src/Cms/ContentInfo.php`：所有 CMS 内容类型共用的顶层容器。
- `src/Cms/*Data.php`：不同 CMS 内容类型的创建、读取、解密或验证逻辑。
- `src/Cms/Recipient/`：五种 RecipientInfo 实现。
- `src/Asn1/`：BER/DER 编解码和值读取层。
- `src/Crypto/`：AES Key Wrap 和 X9.63 KDF。
- `src/Format/`：PEM 与 opaque S/MIME 格式转换。
- `src/X509/`：CMS 所需的证书标识信息提取。
- `tests/run.php`：功能、安全失败路径和格式互转测试。
- `tests/citic.php`：仓库中信银行测试数据验签。

## SignedData 使用示例

### 创建分离签名

```php
<?php

require __DIR__ . '/vendor/autoload.php';

$cms = new PurePhpCms\SignedData();
$content = file_get_contents('message.bin');
$certificate = file_get_contents('signer.crt');
$privateKey = file_get_contents('signer.key');

$signature = $cms->sign(
    $content,
    $certificate,
    $privateKey,
    true,
    'sha256'
);
```

第四个参数为 `true` 时生成分离签名，CMS 中不保存原文。

### 验证分离签名

```php
$result = $cms->verify($signature, $content);

echo $result->digestAlgorithm;
echo $result->content;
```

分离签名验签必须提供与签名时完全一致的二进制原文。不要对内容自动执行换行转换、
字符集转换、JSON 重排或去除空白。

### 验证封装签名

```php
$result = $cms->verify($attachedSignature);
$content = $result->content;
```

### 提供外部签名证书

如果 SignedData 未内嵌签名证书，可将候选证书作为第三个参数传入：

```php
$result = $cms->verify(
    $signature,
    $content,
    [$signerCertificatePem]
);
```

候选证书被用于验证密码学签名，但其可信度仍必须由调用方单独判断。

### PEM 转换

```php
$pem = $cms->toPem($signature);
$result = $cms->verify($pem, $content);
```

## 异常处理

解析失败、算法不受支持、摘要不匹配、签名失败或找不到接收者时会抛出：

```php
PurePhpCms\Exception\CmsException
```

示例：

```php
try {
    $result = $cms->verify($signature, $content);
} catch (PurePhpCms\Exception\CmsException $exception) {
    // 记录内部诊断信息；对外返回统一的验签失败结果。
}
```

## 测试

运行全部测试：

```shell
composer test
```

测试内容包括：

- 临时生成 RSA 和 EC 证书。
- 六种 CMS 内容类型。
- 五种 RecipientInfo。
- 封装/分离、多签名者、SKI、签名属性和 countersignature。
- DER、PEM 和 opaque S/MIME 格式互转。
- 错误证书、密钥、KEK 标识、口令、MAC、摘要和篡改数据的失败路径。
- CMS version 字段及异常 BER 输入。
- 上级仓库中的中信银行证书与真实签名测试数据。
- 修改中信业务原文后必须验签失败。

现有自动测试通过不代表实现已经获得完整验证。正式采用前至少还应完成：

1. 在目标 PHP 7.4/8.x、操作系统和 OpenSSL 版本上运行测试。
2. 使用 OpenSSL CLI、Java、目标银行或厂商 SDK 做双向互操作测试。
3. 增加业务实际使用的证书、算法、超大数据、异常 ASN.1 和模糊测试语料。
4. 由具备密码学和 ASN.1/CMS 经验的人员进行独立代码审计。
5. 根据所在行业和地区要求完成算法、密钥长度及密码产品合规评估。

## 免责声明

本代码按现状提供，不对正确性、安全性、适销性或特定用途适用性作保证。尤其对于金融、
支付、电子签章、身份认证或其他可能造成资金和数据损失的业务，请在充分验证和审计后使用。
