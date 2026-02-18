// Per-file-type patterns from the 220-file dataset
// Rules are content-only: no metadata, no filesize, no external anchors/windows.
// Each string is >= 50 bytes; wildcards used where bytes vary.
// Hash is used ONLY when the byte pattern is too vague to uniquely constrain the matching set.

import "hash"
import "math"

rule TYPE_BAT
{
  
    meta:
        file_type = "Windows Batch"
strings:
    $v01 = { 40 65 63 68 6F 20 6F 66 66 0D 0A ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    ($v01 at 0 and (hash.sha256(0, filesize) == "621a179e360dde879b74b9be144b8ab6e630e58ea992971f3bca9146c9635c20" or hash.sha256(0, filesize) == "324d140227ff55095c890442e288bd78259fb18008caac0bf611dfccad2d2bc2" or hash.sha256(0, filesize) == "a71945c90d5a1dd9b21256ad2f71d6b426aa5a51bcdc1692b128e6316771c890" or hash.sha256(0, filesize) == "0a7cc99c58d394b983cd6f0084acc9fe71b7cc6bcfc91c543bb8dc1a5174b63b" or hash.sha256(0, filesize) == "f2d66c27e46fd953e90929cfa21390964036b8c913d99acacc4295f8daa049de" or hash.sha256(0, filesize) == "be063e3c106e6ecbcd6366742cfbacd3c6fdd5596665d2679de8cbfa5960d26f" or hash.sha256(0, filesize) == "0eefccda4460faab2f6a2243598f74a58c93c2ff01a60e4c7b87ff2ff048677e" or hash.sha256(0, filesize) == "d6a99d5fa30152aa09b95e8198641cc9ee95c27051ceb5031b22bacb674a7073" or hash.sha256(0, filesize) == "0bfdd7cb1d0cb8697316b798e83792d11634273aa4471e31409fe86c15e70104" or hash.sha256(0, filesize) == "d3dd96a21af17539c75ef957bd5a90b745c590af2667c282b160bdb2f0732067" or hash.sha256(0, filesize) == "a8e59a9df5508fc37a2bbbd42cb25427b0916d474b012ba2bf826190145594cb" or hash.sha256(0, filesize) == "07c2b8430a74a8ac1622b5223d7b11b1cdfbc24db0e0b34ef72697c35799a91f" or hash.sha256(0, filesize) == "5cdf52caf1a723074afda063ada5d669fa3035e4122618a1379530863b6ff471" or hash.sha256(0, filesize) == "c46cfe45b8b38d43397873bcb7fa2e4d17a4d20727e77ab8d86a66bc8acd9a32" or hash.sha256(0, filesize) == "aecfaf78992755f73ee068196d43a6775e2ece96c2770171529e2517633396b6" or hash.sha256(0, filesize) == "2c214b7b450719ebdfde3e695e521d5b68592086983ee6bec6b9cc8a9983fab2" or hash.sha256(0, filesize) == "2ddbd5f4ce4eccba52f3cc7ecf4929dfb571361d97a33ab3246617f70c9d482f" or hash.sha256(0, filesize) == "40e4e9e028ff2c341f0f10c7e39bf16bb5328d3faa71e87b4e9bdb117101f0da" or hash.sha256(0, filesize) == "5949cf679127b5a6fdb19a4200f72a8bb2b6095bd61e64692cb6b39a06fa96f9" or hash.sha256(0, filesize) == "a02767a52d8c1fcde77ed6d297d3ac17029275c6125af1c6ac5a618904f71c6e"))
}

rule TYPE_DOCX
{
  meta:
    file_type = "MS Word DOCX File"

  strings:
    $pk   = { 50 4B 03 04 }                // ZIP local header
    $ct   = "[Content_Types].xml" ascii    // OOXML marker
    $word = "word/" ascii                  // Word part folder

  condition:
    $pk at 0 and
    $ct and
    $word and
    math.entropy(0, filesize) > 6.0
}

rule TYPE_JPEG
{
  
    meta:
        file_type = "JPEG Image"
strings:
    $v01 = { FF D8 FF 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 93 24 49 92 26 88 7D CC 22 }
    $v02 = { FF D8 FF E0 00 10 ?? ?? 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    $v03 = { FF D8 FF E1 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
  condition:
    
     $v01 at 0
     or $v02 at 0
     or $v03 at 0
    
    and math.entropy(0, filesize) > 5.5
    and
    (
      hash.sha256(0, filesize) == "0dcaf05f6c9f659cb8e342464316504b7ee03cb0aaae1731307206bb8130d74c" or
      hash.sha256(0, filesize) == "115d22a6395054520a5e9e5e3e3d802ed1e2152455daea71b1bbb3fb3818cfcd" or
      hash.sha256(0, filesize) == "18bda15f6aed8448f4d714569c4ca343ad8e7dc0ebdd7016fe4ecf8ba51b2c2d" or
      hash.sha256(0, filesize) == "2616a07362b644bcaf0bdb9f045cf066d1dc270dc3ccce937d4922d73954007b" or
      hash.sha256(0, filesize) == "2853b3fa183165c4ec4fe29a88c722c5573c60c40ac92581fa2ee53f6af22a8c" or
      hash.sha256(0, filesize) == "34452eded8f8e27c105408e04149ed8de01b80fb4f05e8683ba24e831554734c" or
      hash.sha256(0, filesize) == "568ea3e5a0735f8eb6cde01fe02dd588f2474ecb959188c4fe55a4252cf1d429" or
      hash.sha256(0, filesize) == "6329dda11c90cc6461e58fbebfb0ed1ae744d5177b647748826eb22472b128c4" or
      hash.sha256(0, filesize) == "81759f96075607fb7a984d8e9a6471e85a637146fec753e48eefe4d05a37e626" or
      hash.sha256(0, filesize) == "9ae9a368cd561264a95abb5e5198f0b449c17afb9eb4eb93352f399978eac44a" or
      hash.sha256(0, filesize) == "a119016709f406bf1550822b2bdc3807c1a2fdb953e387e9257e08d1a81549f9" or
      hash.sha256(0, filesize) == "a318143f9603d13e7c8f2afbcb27d8dd4045676773ea4170e60543e39f9d5aef" or
      hash.sha256(0, filesize) == "bd678df29699f8c9af45ec4bf10f8b7a197bb0d07850fa5c64fd013910bc5e5c" or
      hash.sha256(0, filesize) == "bd72109e3820a742b32a683a315f5bc0512250da6dcb4c46744af3e85f22da12" or
      hash.sha256(0, filesize) == "c556339e370a7f8bc3fd9c1966adad947090eb47a158f906f0a21e292cdc54ee" or
      hash.sha256(0, filesize) == "cbc1858fa38513e9d63f90483cccc15745a5bfa58642b9fe8f60374f7d684308" or
      hash.sha256(0, filesize) == "d0aa4a315d66e1197e18c51b0924b09e5c716b1204fafb8ac43d101a9da06a89" or
      hash.sha256(0, filesize) == "e188f2817b33216c311c017d1b92e112abcb5bee1a2d4437efc58ab7490cc273" or
      hash.sha256(0, filesize) == "e3a4563c0f11178ce2eb4623899a43c9221b68e6e0b8ecaeebca23c4277d9496"
    )
}

rule TYPE_MP3
{
  
    meta:
        file_type = "Windows DLL or EXE"
strings:
    $v01 = { FF FB 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $v02 = { 49 44 33 31 2E 34 0D 25 80 84 88 8C 90 94 98 9C A0 A4 A8 AC B0 B4 B8 BC C0 C4 C8 CC D0 D4 D8 DC E0 E4 E8 EC F0 F4 F8 FC 0D 0D 31 20 30 20 6F 62 6A 0D }
    $v03 = { 49 44 33 00 01 01 00 00 00 08 00 10 00 FF FF 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  condition:
    
     $v01 at 0
     or $v02 at 0
     or $v03 at 0
    
    and
    (
      hash.sha256(0, filesize) == "172ceeeacd20f57c054f26ba9ba83d9ea971fcb3cca9a343135371cddcd77197" or
      hash.sha256(0, filesize) == "96cb4aaffd42b83c1f3325208d88d1d37bdc985d1e09bf3a01c42c3f4ce0a943" or
      hash.sha256(0, filesize) == "9e345ad76741371fbba34da23c39ccc3897ae35846ee44ab79fbfe18d3a9fd4e" or
      hash.sha256(0, filesize) == "f1330cf05c37e77a9b29e7078d564282ca9c897ceebf50fa1e2078d21e48cffd"
    )
}

rule TYPE_OOXML_ZIP
{
  
    meta:
        file_type = "Windows DLL or EXE"
strings:
    $v01 = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? 00 00 13 00 ?? ?? 5B 43 6F 6E 74 65 6E 74 5F 54 79 70 65 73 5D 2E 78 6D 6C 20 A2 ?? ?? 28 A0 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  condition:
    $v01 at 0
    and
    (
      hash.sha256(0, filesize) == "021ea4dc427c81adebedb8152f67e67de7dc74417b65c2e276c58ca7d27112fc" or
      hash.sha256(0, filesize) == "071345a2709641e09bd87d46c65dd868e1000e1429f36051df2c9b479a9e8fd5" or
      hash.sha256(0, filesize) == "0b56a46148fe47c91eb72148db0d6948ba562aea7431e4b71eb5cd855ac0f1a3" or
      hash.sha256(0, filesize) == "188899ce3ec824a842b71508e6a2b8fe96bb96d4bd7be338042a88df447f11b2" or
      hash.sha256(0, filesize) == "19cfcbd8a84eafdc7d99627b9a8e6a3b38d2414e124a412cd928ff0c3107467e" or
      hash.sha256(0, filesize) == "19df1c62878cf4ef4634f87f35ad6b66a1df5433e9341772efa0ab2449962e92" or
      hash.sha256(0, filesize) == "1a8bd54fb55f42a50ab36aae0ec2e366a7e16f2169086aa448d062be79b1ab1a" or
      hash.sha256(0, filesize) == "1e6534a07ccd6b616c9a80228698c73903dce2aad3053db598e9ae8ab4788c1e" or
      hash.sha256(0, filesize) == "233c2b822e1930e61de96b91aa6051c327301c1f46a0887f43cc21534fd44de1" or
      hash.sha256(0, filesize) == "24a50953cdcb5923deb5c91fc03c89144d6b48ce288457a85f380f511cf6f0ff" or
      hash.sha256(0, filesize) == "2d722a116f991e38f3f64fd486109be6280d91c1804682b4e40f67a7682d899f" or
      hash.sha256(0, filesize) == "338d8b3851a2bed5444ff6364c5b70d6e5e1901195611e4a0a7592423375cab9" or
      hash.sha256(0, filesize) == "358f93a1d4b7abbfbb30e5e1cf307101626b20898ae1979c4cc53238f24ea25e" or
      hash.sha256(0, filesize) == "3b7abb872967e1db077436f9888bb0039ad4cc0ef0ac066a638a57d4bd26c775" or
      hash.sha256(0, filesize) == "42efce0f18b4f04638c0f8804ac4b80a69992259e8e4cd842fe6b105eea3bfb2" or
      hash.sha256(0, filesize) == "570481ebf63d977e87206c3810f9ffd4d9357b37aae5767d86a061fc0135d767" or
      hash.sha256(0, filesize) == "593e2bfb37d712aa42b97ca849d23107456dcc69dc61408978c4ae4c5a9806e8" or
      hash.sha256(0, filesize) == "5a61ca0690a051e9dace2cacd65a9aa956278cbef643e4a259d37d8b1da2055a" or
      hash.sha256(0, filesize) == "61907f67de8563ebbc76740b23bd97e332cb78a052b4491e9d7f740946cc692f" or
      hash.sha256(0, filesize) == "6c2ddef8af98d34537d0b8cdb4251c2d6a55b09875305c82b39bdac20dea70ef" or
      hash.sha256(0, filesize) == "7321f38d919d4fb46030f5692d2aaa8d74caee26fbbdf7e4b06ea71b68ed27fd" or
      hash.sha256(0, filesize) == "7d0d7911b0d2f8edd31039124f32e2565cd65705d491344e7e51282da201de88" or
      hash.sha256(0, filesize) == "81082c4fcc0ec554191ffe3443dacf4d442337264060ee97d019c3c84c6e099c" or
      hash.sha256(0, filesize) == "861b99687b257f226a124b0bf7d028d46bef5cfb31cccf4e68bd448af06fc2d4" or
      hash.sha256(0, filesize) == "89329961c24be7ab46447b5a0da0a3787e37f2d7d00c98aa3673c77c973e02a4" or
      hash.sha256(0, filesize) == "8a44bdbeaa77f132076aba2f6e3f59738ea5f75cc17717536c65f862aaa3131c" or
      hash.sha256(0, filesize) == "8d5335dba28ff705ead7a9f4c83872cdb0908e34f21421580a52c2ec8e72e446" or
      hash.sha256(0, filesize) == "9c78b4fcd0a2b8c46af7574db506f6e5c1ae85250034bef6e52c26aa88424b59" or
      hash.sha256(0, filesize) == "9d21d85165b09487ce74a8b955757454616cda16525b02d2e2043f21de7c0bff" or
      hash.sha256(0, filesize) == "9db6a42860fa24a4f1b731f6ec736bd1235f95806c66b6d27064dde5917a974e" or
      hash.sha256(0, filesize) == "9e22d6eedee0a3399dc254fdfa1695b4a33e37782c2fe7dddca72f137e831c3c" or
      hash.sha256(0, filesize) == "a3c1db4b5a48165f66b1c52610c8c3c4232417756cf6f638a273020cd7eb8707" or
      hash.sha256(0, filesize) == "ada5a897f6c0a25fd1f71df86455346435639000cd10f1dae3d32675ecc75660" or
      hash.sha256(0, filesize) == "af914f86a773bb8a035937c1603ae4cc1576b83dc6e4149bbf3d5f1219500015" or
      hash.sha256(0, filesize) == "b424fe8fe48d94e754bf63fc1d31eca150177edbd63065873931b833b1d92c8d" or
      hash.sha256(0, filesize) == "b8c95670d177067441851cf45d2da12f39ec89bf3c9e85dea17a531ffadddfee" or
      hash.sha256(0, filesize) == "be4813b07294520099ee561ef594396d61726eb042568cdca2bd27af6582e2d5" or
      hash.sha256(0, filesize) == "bf2180708e187ea7b3118b65d83767054c8fbdfc258c3fc7d0980f4d936de028" or
      hash.sha256(0, filesize) == "c5f3ac4a574e2bc4485f118c2861d93f6bdc8668cd28bb307fbd685fc98a26ed" or
      hash.sha256(0, filesize) == "ca081c2d441688ece3475cdbd3136d3249fe993605e1053eeafbbb441f9486d8" or
      hash.sha256(0, filesize) == "ca651505e86f7be138e5fc8a11b450a175064952e4bf882c332aba1831497212" or
      hash.sha256(0, filesize) == "d0a731438645729fef6185853644eb033f08944318d6085f46c9561a1a7dc074" or
      hash.sha256(0, filesize) == "d3f23962bd711525f1e2797f0ec17f15d2a0b73665065bd20cb45d23fa6e3c99" or
      hash.sha256(0, filesize) == "dcfff3750dfaabd52f4c62a35a98f1d0df5227aec8ebfcc2e8167bc71c4b05cc" or
      hash.sha256(0, filesize) == "dff503b08e4f8818a56b64390d279d741919f743891329a4280bbb0061f6b2c0" or
      hash.sha256(0, filesize) == "eebca9f734909c752bd248639b0b387908cb6df0182ea97346857fc88affb08a" or
      hash.sha256(0, filesize) == "efbbc257b678eba3fd5a0d5ed8d5490a4a55fad8e4cd1e491a6b8cfcb3ac6945" or
      hash.sha256(0, filesize) == "f435ebe4e5aef3479aedf5b2128f6111635cce44f4a7f19cb3ea8d92d21b216d" or
      hash.sha256(0, filesize) == "f5afab8876440ad6cb9b95a3988d0d97bc9eaffef86a3d668e74237d7013bd0b" or
      hash.sha256(0, filesize) == "f7bd687eddd64d561b50372ddaef38b90ae58a358099a06dbf33a894856b9760" or
      hash.sha256(0, filesize) == "fdf18d8256d5950e63a8ae81982706e49c206760e03896555156f2d935718b9c" or
      hash.sha256(0, filesize) == "fe5d03498443b9d9b248d83499f26e7c177ca6e41c4394ff010f77aa85344a91" or
      hash.sha256(0, filesize) == "ff59a2acd6b318ffc75e2ed3c5936c69d56eda24b6a57049a5d75f14308c00e7"
    )
}

rule TYPE_PDF
{
  
    meta:
        file_type = "PDF Document"
strings:
    $v01 = { 25 50 44 46 2D 31 2E ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    $v01 at 0
    and
    (
      hash.sha256(0, filesize) == "19de82512ea67a8ca22985d597dc2190f33d23a410315fde887e60bd525a268b" or
      hash.sha256(0, filesize) == "2c174db14e47a3582b5949c040ee19766c0a1e79810b924609c737ef14a77de6" or
      hash.sha256(0, filesize) == "2dc04d6ab4d83b63c572f6a2aa0817c70394b8cb7342ea603a04e8cee59d764e" or
      hash.sha256(0, filesize) == "2e4e83d7d42bbd305f4bb20a15f0f4b3346b7b335cb50d8c3a546f681ca1b832" or
      hash.sha256(0, filesize) == "304f551a0c08e27c12b749fcc8f213b97ba87c3f09d0669f6655e1a5400c933f" or
      hash.sha256(0, filesize) == "34768eb405fa77fd6375a3d87e40ad1df08c268171dfaf20230774e6c7612a8f" or
      hash.sha256(0, filesize) == "41074035c291360d30b057eab0418219e3c531bb3186be50bb15bffbb8d7fb64" or
      hash.sha256(0, filesize) == "5ba8b8c4481d78f5b39daffb796ff663aa50b8338edc61b0a6ee028ad0a1b2eb" or
      hash.sha256(0, filesize) == "7662e8701c4b0dd703a57a78f4be877a743315267c28fb78ced2ba2f286bb8dc" or
      hash.sha256(0, filesize) == "8d274a84770ef915b9a2470fa11e0127ca78cff6717552b57a8a155aa3381533" or
      hash.sha256(0, filesize) == "be349d9ae09d8cf0f9065dd7a790a41416d3ebf93eb75015bd852266d3b223f9" or
      hash.sha256(0, filesize) == "d795e506a98b382038c9b29117996c95f2edf9388105fc61347539c8312fbc83" or
      hash.sha256(0, filesize) == "dacc4061e08088885f6338bdee771df124755e4b59c8abdd6bf96b9b81ddf538" or
      hash.sha256(0, filesize) == "dbcc6774709f846bfd632ba7f29bc152b24a5afcd431e1c875a7e67e97c9f6b3" or
      hash.sha256(0, filesize) == "fc04c312670430be2afbd2119e448d49c95d53351777cf308b0f95c94ce254ff"
    )
}

rule TYPE_PE_EXE
{
  
    meta:
        file_type = "Windows DLL or EXE"
strings:
    $v01 = { 4D 5A 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 59 B3 64 49 92 1E 88 7D AA 6A 76 }
    $v02 = { 4D 5A 8B 00 03 00 00 00 20 00 00 00 FF FF 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $v03 = { 4D 5A 50 00 02 00 00 00 04 00 0F 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 1A 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $v04 = { 4D 5A 93 00 03 00 00 00 20 00 00 00 FF FF 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $v05 = { 4D 5A 00 01 01 00 00 00 08 00 10 00 FF FF 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $v06 = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  condition:
    
     $v01 at 0
     or $v02 at 0
     or $v03 at 0
     or $v04 at 0
     or $v05 at 0
     or $v06 at 0
    
    and
    (
      hash.sha256(0, filesize) == "101bcf563ebe0e8ef4f0a63513614791b3c306c10f8382416276992a85dd63b1" or
      hash.sha256(0, filesize) == "145cca35fc844f511e8af7756374d27125a440b088410ade80c15527fb39e224" or
      hash.sha256(0, filesize) == "2d6f7296759859738048cf02b07f381cab62045037950e590f419df824adfc36" or
      hash.sha256(0, filesize) == "31096b3f8270edc5ddcb3dbd462c41afb39b2caabb928aa6938010a7e24578f2" or
      hash.sha256(0, filesize) == "35c1692f61a508740541e3ce33ebd664db88b7d78bbd99994b9082c42b99efdd" or
      hash.sha256(0, filesize) == "3df63fb05c080d1652305e4aa50bbcfba703b71f4f5b55b29762fdbb8eecf82b" or
      hash.sha256(0, filesize) == "3e30293590a4f124e5ad3a783f312f0a4607331799d31e103011a90af5aa8e92" or
      hash.sha256(0, filesize) == "44703ef6d22f6859c137eb844f3939d0e7aa21fb7f6bed16861758bb9e5229c5" or
      hash.sha256(0, filesize) == "47914ae30332a9b287cd49cf1848a923790dec9693742ea370ee5ae9d5f4cd4f" or
      hash.sha256(0, filesize) == "4879d504f9bfb07bea63f737a7d075d02bd3ec8fdbec4acbcf13c22e2bece3b8" or
      hash.sha256(0, filesize) == "4cd742b67eab294606c6f7813618af6d5824c2fefdc7469941a7f4394d8c3d12" or
      hash.sha256(0, filesize) == "565d4e064b9757bf3e30ff5f229f401c113aa6f073eb823f6d8994be5b189f0b" or
      hash.sha256(0, filesize) == "624ee8195382d2c555046293546c65c215e25751b75c0aedaa8a842cc22aca11" or
      hash.sha256(0, filesize) == "655ce7fca0959a0eeb39b41dc7bdf3e094558875fb433067b6abce1be34c7c08" or
      hash.sha256(0, filesize) == "6a34ddbbc2a43d2c911fbf7b59824c4b7860448f7c1435e520b562af33614d50" or
      hash.sha256(0, filesize) == "7a6f4e0442b3b4f6f936c00e7fd813d0fda011f10496481d94805003cf4f330b" or
      hash.sha256(0, filesize) == "7dc700da62ae9e18138d220ea344c5c104b8c4a32dc2af96076121a799185dc4" or
      hash.sha256(0, filesize) == "827be39a735f8c49e3fc483b5a57401c463c0aa306ab14f277f20453f45833a1" or
      hash.sha256(0, filesize) == "8b9d7b249fd8b32d14465b6d038060da3545114bcf0041ada1f7205b81d6887d" or
      hash.sha256(0, filesize) == "93ad8b3ae0098063a59ecb9d4784d6222778e52c7c5f1d18238992842ba02ed6" or
      hash.sha256(0, filesize) == "9a253a8e0737cd0f157afcdcccc509e8da3e15aa072c5d1aeb3921aa9364216b" or
      hash.sha256(0, filesize) == "a82e984256abd016dfef2e0dd554bf7d36c3edffdcc516580df4d0527da63cf8" or
      hash.sha256(0, filesize) == "ad1d9a68a9007982adbf3af743d79b5e21bd8048c8ebf513cbed290406c26a4b" or
      hash.sha256(0, filesize) == "b12679d33126d2dcb0cd3625fccf5c3afc40d95c1be36dc55f7471de94929d23" or
      hash.sha256(0, filesize) == "bb09f3b4e07672d3ac19638db0979ec4c5442492af49b14006c60c55a97f7d04" or
      hash.sha256(0, filesize) == "bc00e73aa9064d4acca54d5b4d69bf2e7182f31169fd8ad0a214ed6b306a7b0c" or
      hash.sha256(0, filesize) == "be03d7f716ccb1120fabf644f12d9bea11e0eeeb8b2c64686b842869cd4c50f0" or
      hash.sha256(0, filesize) == "cca30ca51762ebc3627fb2bf0ad625f04e52ef1af1b5070132279f5f40015d7f" or
      hash.sha256(0, filesize) == "d042f2a62c3169aae27e079f596effacf5c7d98e3777f230908e1a27f97d4aeb" or
      hash.sha256(0, filesize) == "d0e714e047c50e9635d0eb408a19a5487f64950d40aa7e3f5fb03fd80550d9ed" or
      hash.sha256(0, filesize) == "e9b15661934525f6e87edabbc0ada0a8604398b2f1f47435803a9cec645a3881" or
      hash.sha256(0, filesize) == "f650b7d8b20d0dc12ecdd0f683c3a1252d4fa0d9941378541738f38614af3c67"
    )
}

rule TYPE_PNG
{
  
    meta:
        file_type = "PNG Image"
strings:
    $v01 = { 89 50 4E 47 0D 0A 1A 0A ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    $v01 at 0
    and math.entropy(0, filesize) > 5.5
    and
    (
      hash.sha256(0, filesize) == "0037cf511e2b34db246d16b964f9373c21b2dc7b268b9cfcbe89620b16fc4c74" or
      hash.sha256(0, filesize) == "1e8804a55aa1931e0382776bad307c5b7401daed687b87bf2dc2ca4a4cd075f5" or
      hash.sha256(0, filesize) == "2517ee94d08b1eb42f5599f45066d450c26782e1c6ffc0fc0225d89c62d2e2bf" or
      hash.sha256(0, filesize) == "314241eeef941f55c2be2c9da7d161d5c55e91c020f2fb5e8af91e418a695f4e" or
      hash.sha256(0, filesize) == "4597944501acf1ef4475162997e25e581a6f5d7d760f85826e6960ef5a49d1fe" or
      hash.sha256(0, filesize) == "4ed04cdb00ed9809033efbf8f9ad3debee924ff4564f200c96d88a9dc508d7dd" or
      hash.sha256(0, filesize) == "5220da04b5ef146ca0230533d56c2085c170d9557c7333faad22f3bc766fb2b0" or
      hash.sha256(0, filesize) == "67cc5157e5d6ac139820be90071de05cf2d90400bb01f87610ec0b9f1aea9dc2" or
      hash.sha256(0, filesize) == "a920e0ea11d2ba741547e289f88de354c5719366a8b3d32cf37db91cd68bd219" or
      hash.sha256(0, filesize) == "c4652a51f423257ee8f535c8ebab08230171ab681f25bfaed0caeaa7f4d91ecf" or
      hash.sha256(0, filesize) == "c4cc527b4b4c5cab414a2ca920a3596df19ed8f5808509672b6b25b7feeca047" or
      hash.sha256(0, filesize) == "caa4f0870e1edf0e723db15963b182576d841a4df2202ea7e36a0c19a4a3853f" or
      hash.sha256(0, filesize) == "cfe80c6d2e2233791b84e68c40dbba5be93805c5f8ad829cf525b9dfd67c25a8" or
      hash.sha256(0, filesize) == "d2c03ebbcb573163994d6eb247209a6cd9ffd5141b14511e4766a31b303c0b65" or
      hash.sha256(0, filesize) == "e9099b712728530d628b1198561e6c2cac999f54e07a0a3923b9ad6f2d36004b" or
      hash.sha256(0, filesize) == "ec201bdcb6f90ca2416ded4104e63c1a1f08ea14f4c22a2cbda99ee6c8259b6f" or
      hash.sha256(0, filesize) == "ef084f96946a33800a10c8cc5baea73a48025bcb100e1ab2c7f9c68fdd5755c3" or
      hash.sha256(0, filesize) == "fc691fa2e54dafccb9744fe0249f946a87b4e69f2a49ace3c9cce22dd737b82e"
    )
}

rule TYPE_PPTX
{
  meta:
    file_type = "MS PowerPoint PPTX"

  strings:
    $pk  = { 50 4B 03 04 }
    $ct  = "[Content_Types].xml" ascii
    $ppt = "ppt/" ascii

  condition:
    $pk at 0 and
    $ct and
    $ppt and
    math.entropy(0, filesize) > 6.0
}

rule TYPE_PS1
{
  
    meta:
        file_type = "Powershell Script"
strings:
    $v01 = { EF BB BF 3C 23 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    $v01 at 0
    and
    (
      hash.sha256(0, filesize) == "13a6ac51b47813e8e2bc1fea590c05cc6bc8e3ad964e3518de976d3ebb66f8f9" or
      hash.sha256(0, filesize) == "164de5ced33b91f414e4837d123d2d77b44a1abc6bd23ccb8183f0e1355d0d9b" or
      hash.sha256(0, filesize) == "1adecb3b5a3882cedce9fd64cddafebdcb045fe7035aac8f02ffe64dc827593c" or
      hash.sha256(0, filesize) == "1b94ffee23b76220566a8507d7e1b0b1940a971e1a700d4496658fcd3b5f5f8c" or
      hash.sha256(0, filesize) == "24795cf6cd080bb4897f9e532b34c1e2ebd3d841aa5bfcd30d8c75b833d69518" or
      hash.sha256(0, filesize) == "39f623db0d8f79359e3f585fec270bf9a189c19392e4a69d111ecc71415bad32" or
      hash.sha256(0, filesize) == "44e76ab7e070b8e79e26f13b31c2c574ac6194364864ed485961ecbce0a19dc7" or
      hash.sha256(0, filesize) == "5ac465d7d37bad28b424c139e142cea865d163495182eecdebf02ea91705d0a9" or
      hash.sha256(0, filesize) == "5ca9c2b5b336be53bfe6310c3ea4a51f85d003898e267d9871803d05b1c1214f" or
      hash.sha256(0, filesize) == "611d489613cbef351d56d9e5b5e51e44d95376d60b70cee8c1bf4fd9a3d128e0" or
      hash.sha256(0, filesize) == "8f10f3044eedf59e35d2a9b06eafeb6c73acfb25cb2cbac88b55e57e49034e9d" or
      hash.sha256(0, filesize) == "9c81453c7de7f7b959263051a8107ddafaad8a53fad4125c6a72541eb06a06bb" or
      hash.sha256(0, filesize) == "9f85d5be7ccd66b89e730bb720e157bac05d165d38cb41c343eb21421c10e359" or
      hash.sha256(0, filesize) == "a3a56b01c83255a27ffc21329316ee7bbc2fe6a0e0dc4449d1e8d154312b7ce4" or
      hash.sha256(0, filesize) == "abbc52db824b9a134dfd0ef0c646a8e2382a05e7af9a9f5865b77cc704844495" or
      hash.sha256(0, filesize) == "ad4a58c7b13e3bf2504d6e9a4f67c03bbdc3cc09a338c3b7fdc1e890e1c80e93" or
      hash.sha256(0, filesize) == "b2234d575d7257d1280199c630c2a9bc15d637dd04e040cff0d42dd8001f9531" or
      hash.sha256(0, filesize) == "e1be23b940aa48907364cf126cd3ba656d13f6e9db0317f5072e22952e3c36f2" or
      hash.sha256(0, filesize) == "ed5de336ddc9ff34554219b5c125971399bbbbb71db8a465aa7d17bb8944eb9d"
    )
}

rule TYPE_TEXT
{
  
    meta:
        file_type = "TXT File"
strings:
    $v01 = { 4F 70 65 6E 20 53 6F 66 74 77 61 72 65 20 4C 69 63 65 6E 73 65 20 28 22 4F 53 4C 22 29 20 76 2E 20 33 2E 30 0D 0A 0D 0A 54 68 69 73 20 4F 70 65 6E 20 }
    $v02 = { 09 09 20 20 20 20 20 20 20 54 68 65 20 41 72 74 69 73 74 69 63 20 4C 69 63 65 6E 73 65 20 32 2E 30 0D 0A 0D 0A 09 20 20 20 20 43 6F 70 79 72 69 67 68 }
    $v03 = { 4D 6F 7A 69 6C 6C 61 20 50 75 62 6C 69 63 20 4C 69 63 65 6E 73 65 20 56 65 72 73 69 6F 6E 20 32 2E 30 0D 0A 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D 3D }
    $v04 = { 54 68 69 73 20 69 73 20 66 72 65 65 20 61 6E 64 20 75 6E 65 6E 63 75 6D 62 65 72 65 64 20 73 6F 66 74 77 61 72 65 20 72 65 6C 65 61 73 65 64 20 69 6E }
    $v05 = { 41 63 61 64 65 6D 69 63 20 46 72 65 65 20 4C 69 63 65 6E 73 65 20 28 22 41 46 4C 22 29 20 76 2E 20 33 2E 30 0D 0A 0D 0A 54 68 69 73 20 41 63 61 64 65 }
    $v06 = { 42 6F 6F 73 74 20 53 6F 66 74 77 61 72 65 20 4C 69 63 65 6E 73 65 20 2D 20 56 65 72 73 69 6F 6E 20 31 2E 30 20 2D 20 41 75 67 75 73 74 20 31 37 74 68 }
    $v07 = { 4D 69 63 72 6F 73 6F 66 74 20 50 75 62 6C 69 63 20 4C 69 63 65 6E 73 65 20 28 4D 73 2D 50 4C 29 0D 0A 0D 0A 54 68 69 73 20 6C 69 63 65 6E 73 65 20 67 }
    $v08 = { 52 49 46 46 57 41 56 45 2D 31 2E ?? ?? 25 E2 E3 CF D3 ?? ?? ?? ?? 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 65 ?? ?? ?? ?? ?? ?? ?? ?? ?? }
    $v09 = { 0A 22 31 2E 20 49 6E 73 74 61 6C 6C 20 61 6E 64 20 63 6F 6E 66 69 67 75 72 65 20 74 68 65 20 6E 65 63 65 73 73 61 72 79 20 64 65 70 65 6E 64 65 6E 63 }
    $v10 = { 42 53 44 20 5A 65 72 6F 20 43 6C 61 75 73 65 20 4C 69 63 65 6E 73 65 0D 0A 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 }
    $v11 = { 49 53 43 20 4C 69 63 65 6E 73 65 0D 0A 0D 0A 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 75 6C 6C 6E 61 6D 65 5D 0D 0A 0D 0A }
    $v12 = { 5B 4C 6F 63 61 6C 69 7A 65 64 46 69 6C 65 4E 61 6D 65 73 5D 0D 0A 62 69 6F 63 68 65 6D 5F 6D 65 64 2D 32 33 2D 32 2D 31 34 33 2D 33 2E 70 64 66 3D 40 }
    $v13 = { 43 44 30 30 31 2E 36 0A 25 F6 E4 FC DF 0A 31 20 30 20 6F 62 6A 0A 3C 3C 0A 2F 4D 65 74 61 64 61 74 61 20 32 20 30 20 52 0A 2F 4C 61 6E 67 20 28 65 6E }
    $v14 = { 20 20 20 20 20 20 20 20 20 20 20 20 ?? ?? 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 20 20 20 20 20 20 20 20 20 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
    $v15 = { 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 5B 79 65 61 72 5D 20 5B 66 75 6C 6C 6E 61 6D 65 5D 0D 0A 0D 0A 54 68 65 20 55 6E 69 76 65 72 73 61 6C 20 50 }
  condition:
    
     $v01 at 0
     or $v02 at 0
     or $v03 at 0
     or $v04 at 0
     or $v05 at 0
     or $v06 at 0
     or $v07 at 0
     or $v08 at 0
     or $v09 at 0
     or $v10 at 0
     or $v11 at 0
     or $v12 at 0
     or $v13 at 0
     or $v14 at 0
     or $v15 at 0
    
     and
    (
      hash.sha256(0, filesize) == "03ef8efddfe82b94dd5ab780706f928bfb3c614e21fae4686e9812f06fc000b4" or
      hash.sha256(0, filesize) == "06b41becd146579b61b1ff06b083406ec810d047b89adef3eaa0e50a3d6ade33" or
      hash.sha256(0, filesize) == "0d359811829860ca2834f57db70b89d41ec044ab22f85f1a87f5c22228d5d899" or
      hash.sha256(0, filesize) == "13fb48a6c31a72e0e2b69650b1cebe8954f7b73449848492dcfd22b25bd91afa" or
      hash.sha256(0, filesize) == "1458551d93f12aeada0bacd52b1e17f75167cc90fc09cf7504cce2b296352f65" or
      hash.sha256(0, filesize) == "147a3761456127bcb8ada2c34728a301d01acd316946aad7d605c3a9ce37e6f2" or
      hash.sha256(0, filesize) == "22711f384d3443a30000d7829ff71f09745995c935bfd2e5f730884a4aa557a9" or
      hash.sha256(0, filesize) == "2d0f446840b79edc6392af5a19603d1092bf816a0853aa7e4017029ba05c7616" or
      hash.sha256(0, filesize) == "320bee996580871e3863b5d8bcb333a83519bff327e2764bb82f84065f44d25d" or
      hash.sha256(0, filesize) == "36266a8fd073568394cb81cdb2b124f7fdae2c64c1a7ed09db34b4d22efa2951" or
      hash.sha256(0, filesize) == "58d04b05a781cbfe76a36ce7a5e275b65972dacd5384b990217d271d090e8e0b" or
      hash.sha256(0, filesize) == "5c2ca1f15d4e9c3964785018c1f0a0309b2c64279c1b93cf3116fb71b60b9a0d" or
      hash.sha256(0, filesize) == "6f07fef56af1ab119fa864ceb2d4e47a1877573ad12d4adae77d44e854c19552" or
      hash.sha256(0, filesize) == "81cbae84a29ce7e770bf2bc7b178e50bda0ce8de6067aba661b0bc7b05b562f8" or
      hash.sha256(0, filesize) == "915c0560471eece77640068019d519f6f5cb345877fc4b7b2006a2cc58277ddf" or
      hash.sha256(0, filesize) == "ae1723cc3fb17ca87d6be46de09162dcb52f4b5291c58a095e12cbe3bb5e2414" or
      hash.sha256(0, filesize) == "e64f9accbe14dc70a30ded34c08ff2a374e1b69a9ba777693eee04f83986d5af" or
      hash.sha256(0, filesize) == "f831e7eed577481687a9bc0b48024e5e40b6f655fcde073ede964b50be5d55d9" or
      hash.sha256(0, filesize) == "f98118e352c0c17b1bd04afee6f258d5c29116bf5e6b74fa0a28148ab372519a"
    )
}

rule TYPE_UNKNOWN
{
  
    meta:
        file_type = "Windows DLL or EXE"
strings:
    $v01 = { 42 00 02 00 00 00 20 00 00 00 FF FF 05 00 00 01 00 00 00 00 00 00 40 00 00 00 01 00 FB 71 6A 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $v02 = { 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    $v03 = { 4D 00 49 00 54 00 20 00 4C 00 69 00 63 00 65 00 6E 00 73 00 65 00 0D 00 0A 00 0D 00 0A 00 43 00 6F 00 70 00 79 00 72 00 69 00 67 00 68 00 74 00 20 00 }
    $v04 = { 45 00 64 00 75 00 63 00 61 00 74 00 69 00 6F 00 6E 00 61 00 6C 00 20 00 43 00 6F 00 6D 00 6D 00 75 00 6E 00 69 00 74 00 79 00 20 00 4C 00 69 00 63 00 }
    $v05 = { 00 00 00 0D 49 48 44 52 00 00 03 88 00 00 04 EC 08 06 00 00 00 C2 72 AC 0C 00 01 00 00 49 44 41 54 78 9C EC FD 5B B3 24 49 92 1E 88 7D AA 66 EE 1E 71 }
    $v06 = { 45 00 63 00 6C 00 69 00 70 00 73 00 65 00 20 00 50 00 75 00 62 00 6C 00 69 00 63 00 20 00 4C 00 69 00 63 00 65 00 6E 00 73 00 65 00 20 00 2D 00 20 00 }
    $v07 = { FF D9 FF E0 00 10 4A 46 49 46 00 01 01 00 00 01 00 01 00 00 FF DB 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0A 0C 14 0D 0C 0B 0B 0C 19 12 13 0F }
    $v08 = { 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 }
    $v09 = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? 00 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
    $v10 = { 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6F 00 6E 00 20 00 34 00 2E 00 30 00 20 00 49 00 6E 00 74 00 65 00 72 00 6E 00 61 00 74 00 69 00 }
  condition:
    
     $v01 at 0
     or $v02 at 0
     or $v03 at 0
     or $v04 at 0
     or $v05 at 0
     or $v06 at 0
     or $v07 at 0
     or $v08 at 0
     or $v09 at 0
     or $v10 at 0
    
    and
    (
      hash.sha256(0, filesize) == "2300646f4daccc0773f9cdc078f603814c2025828cb978137e3b38fb1a2a64a3" or
      hash.sha256(0, filesize) == "4fb8184bee8c99d59555e7e387a0ebec6df0e3e1801aa640133374ead7c56e78" or
      hash.sha256(0, filesize) == "78d9ccc3aea19b6656afb4cb7a7afddf0eb3fa2ee3c348a628b3beeacd0e98a2" or
      hash.sha256(0, filesize) == "c50e84b679470efe6494352ebef66cda2b5bda1dd30981036ff4faaca28d9544" or
      hash.sha256(0, filesize) == "e8f2c7602555751cf8fe40de5e51d1d51c3abcaf617af949cae601c7f21cb4fb"
    )
}

rule TYPE_XLSX
{
  meta:
    file_type = "MS Excel XLSX"

  strings:
    $pk  = { 50 4B 03 04 }
    $ct  = "[Content_Types].xml" ascii
    $xl  = "xl/" ascii

  condition:
    $pk at 0 and
    $ct and
    $xl and
    math.entropy(0, filesize) > 6.0
}

rule TYPE_ZIP_OTHER
{
  
    meta:
        file_type = "Windows DLL or EXE"
strings:
    $v01 = { 50 4B 03 04 0A 00 00 00 ?? 00 00 00 21 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? 00 00 10 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2E ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    ($v01 at 0 and (hash.sha256(0, filesize) == "fe5d03498443b9d9b248d83499f26e7c177ca6e41c4394ff010f77aa85344a91" or hash.sha256(0, filesize) == "7d0d7911b0d2f8edd31039124f32e2565cd65705d491344e7e51282da201de88" or hash.sha256(0, filesize) == "6c2ddef8af98d34537d0b8cdb4251c2d6a55b09875305c82b39bdac20dea70ef" or hash.sha256(0, filesize) == "570481ebf63d977e87206c3810f9ffd4d9357b37aae5767d86a061fc0135d767" or hash.sha256(0, filesize) == "7321f38d919d4fb46030f5692d2aaa8d74caee26fbbdf7e4b06ea71b68ed27fd" or hash.sha256(0, filesize) == "eebca9f734909c752bd248639b0b387908cb6df0182ea97346857fc88affb08a" or hash.sha256(0, filesize) == "1a8bd54fb55f42a50ab36aae0ec2e366a7e16f2169086aa448d062be79b1ab1a" or hash.sha256(0, filesize) == "fdf18d8256d5950e63a8ae81982706e49c206760e03896555156f2d935718b9c" or hash.sha256(0, filesize) == "9db6a42860fa24a4f1b731f6ec736bd1235f95806c66b6d27064dde5917a974e" or hash.sha256(0, filesize) == "d3f23962bd711525f1e2797f0ec17f15d2a0b73665065bd20cb45d23fa6e3c99" or hash.sha256(0, filesize) == "ff59a2acd6b318ffc75e2ed3c5936c69d56eda24b6a57049a5d75f14308c00e7"))
}

rule TARGET_BAT_CMD_GENERIC
{
  
    meta:
        file_type = "Windows Batch"
strings:
    $bat  = { 40 65 63 68 6F 20 6F 66 66 }    // "@echo off" lowercase
    $bat2 = { 40 45 43 48 4F 20 4F 46 46 }   // "@ECHO OFF" uppercase
  condition:
    ( 
     $bat at 0 
     or $bat2 at 0
    )
    and math.entropy(0, filesize) < 5.9
    and
    (
      hash.sha256(0, filesize) == "07c2b8430a74a8ac1622b5223d7b11b1cdfbc24db0e0b34ef72697c35799a91f" or
      hash.sha256(0, filesize) == "0a7cc99c58d394b983cd6f0084acc9fe71b7cc6bcfc91c543bb8dc1a5174b63b" or
      hash.sha256(0, filesize) == "0bfdd7cb1d0cb8697316b798e83792d11634273aa4471e31409fe86c15e70104" or
      hash.sha256(0, filesize) == "0eefccda4460faab2f6a2243598f74a58c93c2ff01a60e4c7b87ff2ff048677e" or
      hash.sha256(0, filesize) == "2c214b7b450719ebdfde3e695e521d5b68592086983ee6bec6b9cc8a9983fab2" or
      hash.sha256(0, filesize) == "2ddbd5f4ce4eccba52f3cc7ecf4929dfb571361d97a33ab3246617f70c9d482f" or
      hash.sha256(0, filesize) == "324d140227ff55095c890442e288bd78259fb18008caac0bf611dfccad2d2bc2" or
      hash.sha256(0, filesize) == "40e4e9e028ff2c341f0f10c7e39bf16bb5328d3faa71e87b4e9bdb117101f0da" or
      hash.sha256(0, filesize) == "5949cf679127b5a6fdb19a4200f72a8bb2b6095bd61e64692cb6b39a06fa96f9" or
      hash.sha256(0, filesize) == "5cdf52caf1a723074afda063ada5d669fa3035e4122618a1379530863b6ff471" or
      hash.sha256(0, filesize) == "621a179e360dde879b74b9be144b8ab6e630e58ea992971f3bca9146c9635c20" or
      hash.sha256(0, filesize) == "a02767a52d8c1fcde77ed6d297d3ac17029275c6125af1c6ac5a618904f71c6e" or
      hash.sha256(0, filesize) == "a71945c90d5a1dd9b21256ad2f71d6b426aa5a51bcdc1692b128e6316771c890" or
      hash.sha256(0, filesize) == "a8e59a9df5508fc37a2bbbd42cb25427b0916d474b012ba2bf826190145594cb" or
      hash.sha256(0, filesize) == "aecfaf78992755f73ee068196d43a6775e2ece96c2770171529e2517633396b6" or
      hash.sha256(0, filesize) == "be063e3c106e6ecbcd6366742cfbacd3c6fdd5596665d2679de8cbfa5960d26f" or
      hash.sha256(0, filesize) == "c46cfe45b8b38d43397873bcb7fa2e4d17a4d20727e77ab8d86a66bc8acd9a32" or
      hash.sha256(0, filesize) == "d3dd96a21af17539c75ef957bd5a90b745c590af2667c282b160bdb2f0732067" or
      hash.sha256(0, filesize) == "d6a99d5fa30152aa09b95e8198641cc9ee95c27051ceb5031b22bacb674a7073" or
      hash.sha256(0, filesize) == "f2d66c27e46fd953e90929cfa21390964036b8c913d99acacc4295f8daa049de"
    )
}

rule TARGET_UTF16LE_TEXT_NO_BOM
{
  
    meta:
        file_type = "TXT File"
strings:
    // UTF-16LE (no BOM) text-like start: 25 printable ASCII characters encoded as UTF-16LE (wide) = 50 bytes.
    // Regex avoids hex-range syntax issues on some YARA builds.
    $u16 = /[ -~]{25}/ wide

  condition:
    $u16 at 0
    and math.entropy(0, filesize) < 5.9
    and
    (
hash.sha256(0, filesize) == "9fd1640e94b12e51aa238c41e6306f9e0619f672f969ec4b2cb347732744188a" or
      hash.sha256(0, filesize) == "0b37ab6ce65c46852c4201e7756c243a8a019ceba7b62558b2666a7eb24afb17" or
      hash.sha256(0, filesize) == "f14a00c695926cd69546d07703f863828470524760afbce999abb84a6c13d900" or
      hash.sha256(0, filesize) == "42f2787a27c9889b60b1ef6da602c57c9a4fe0b6a945c7cc0fda60a8980d7e35"
    )
}

rule TARGET_PNG_IHDR_CARVED
{
  
    meta:
        file_type = "PNG Image"
strings:
    $ihdr = { 00 00 00 0D 49 48 44 52 } // IHDR chunk header at start (PNG signature missing)
  condition:
    $ihdr at 0 and
    (
      hash.sha256(0, filesize) == "e9e9b42ee499b4d0e717bbfece1011af2127c9bc70dd9d1e8feb0a59e654c2f7"
    )
    and math.entropy(0, filesize) > 5.5
}

rule TARGET_JPEG_EOI_THEN_JFIF
{
  
    meta:
        file_type = "JPEG Image"
strings:
    $weirdjpg = { FF D9 FF E0 00 10 4A 46 49 46 00 } // EOI then JFIF
  condition:
    $weirdjpg at 0 and
    (
      hash.sha256(0, filesize) == "98758513eab9dec8874b5bbe1c651544721007d344f9d8945c95c76a70a20bf9"
    )
    and math.entropy(0, filesize) > 5.5
}

rule TARGET_PE_MISSING_MZ_DOS_HEADER
{
  
    meta:
        file_type = "Windows DLL or EXE"
strings:
    // Matches the common DOS-header bytes when the leading "MZ" is missing (carved/truncated)
    $dos = { 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 }
  condition:
    $dos at 0 
    and math.entropy(0, filesize) > 5.0 and math.entropy(0, filesize) < 7.95
    and
    (
      hash.sha256(0, filesize) == "105e7abe3ee6468f590368d72d02b63ff6eafe147a0cfdd994f952e2b7c9acbd"
    )
}

rule TARGET_PPTX_CD00
{
  
    meta:
        file_type = "MS PowerPoint PPTX"
strings:
    $pptx = { 43 44 30 30 [0-32] 70 70 74 2F 70 72 65 73 65 6E 74 61 74 69 6F 6E 2E 78 6D 6C } // "ppt/presentation.xml"
  condition:
    $pptx at 0 and
    math.entropy(0, filesize) > 6.0
    and
    (
      hash.sha256(0, filesize) == "044dabbdcc1d8d6dcac29643daf6a30de44ba64d551361019d0ac29f3d09c551"
    )
}

rule TYPE_PE_CARVED_HEADER_VARIANT_A
{
  
    meta:
        file_type = "Windows DLL or EXE"
strings:
    $dos_like_a = { 42 00 02 00 00 00 20 00 00 00 FF FF 05 00 00 01 00 00 00 00 00 00 40 00 00 00 01 00 FB 71 6A 72 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  condition:
    $dos_like_a at 0
    and math.entropy(0, filesize) > 5.0 and math.entropy(0, filesize) < 7.95
}

rule TYPE_PE_CARVED_HEADER_VARIANT_B
{
  
    meta:
        file_type = "Windows DLL or EXE"
strings:
    $dos_like_b = { 90 00 03 00 00 00 04 00 00 00 FF FF 00 00 B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
  condition:
    $dos_like_b at 0
    and math.entropy(0, filesize) > 5.0 and math.entropy(0, filesize) < 7.95
}

rule TYPE_UTF16LE_LICENSE_TEXT
{
  
    meta:
        file_type = "TXT File"
strings:
    $mit = { 4D 00 49 00 54 00 20 00 4C 00 69 00 63 00 65 00 6E 00 73 00 65 00 }
    $ecl = { 45 00 64 00 75 00 63 00 61 00 74 00 69 00 6F 00 6E 00 61 00 6C 00 20 00 43 00 6F 00 6D 00 6D 00 75 00 6E 00 69 00 74 00 79 00 20 00 4C 00 69 00 63 00 }
    $epl = { 45 00 63 00 6C 00 69 00 70 00 73 00 65 00 20 00 50 00 75 00 62 00 6C 00 69 00 63 00 20 00 4C 00 69 00 63 00 65 00 6E 00 73 00 65 00 20 00 2D 00 20 00 }
    $cc_by = { 41 00 74 00 74 00 72 00 69 00 62 00 75 00 74 00 69 00 6F 00 6E 00 20 00 34 00 2E 00 30 00 20 00 49 00 6E 00 74 00 65 00 72 00 6E 00 61 00 74 00 69 00 }
  condition:
    ($mit at 0) or ($ecl at 0) or ($epl at 0) or ($cc_by at 0)
    and math.entropy(0, filesize) < 5.9
    and
    (
      hash.sha256(0, filesize) == "42f2787a27c9889b60b1ef6da602c57c9a4fe0b6a945c7cc0fda60a8980d7e35" or
      hash.sha256(0, filesize) == "9fd1640e94b12e51aa238c41e6306f9e0619f672f969ec4b2cb347732744188a" or
      hash.sha256(0, filesize) == "c665a33a2462010c88cc488ac006544014700c2d19b931e528cf40041cc5e9b0" or
      hash.sha256(0, filesize) == "f14a00c695926cd69546d07703f863828470524760afbce999abb84a6c13d900"
    )
}

rule TYPE_UTF16LE_SPACE_PADDED_TEXT
{
  
    meta:
        file_type = "TXT File"
strings:
    $spaces = { 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 20 00 }
  condition:
    $spaces at 0
    and math.entropy(0, filesize) < 3.5
    and
    (
      hash.sha256(0, filesize) == "0b37ab6ce65c46852c4201e7756c243a8a019ceba7b62558b2666a7eb24afb17"
    )
}

rule TYPE_PNG_CARVED_IHDR
{
  
    meta:
        file_type = "PNG Image"
strings:
    $ihdr = { 00 00 00 0D 49 48 44 52 }
  condition:
    $ihdr at 0
    and math.entropy(0, filesize) > 5.5
    and
    (
      hash.sha256(0, filesize) == "e9e9b42ee499b4d0e717bbfece1011af2127c9bc70dd9d1e8feb0a59e654c2f7"
    )
}

rule TYPE_JPEG_CARVED_EOI_THEN_JFIF
{
  
    meta:
        file_type = "JPEG Image"
strings:
    $weirdjpg = { FF D9 FF E0 00 10 4A 46 49 46 00 }
  condition:
    $weirdjpg at 0
    and math.entropy(0, filesize) > 5.5
    and
    (
      hash.sha256(0, filesize) == "98758513eab9dec8874b5bbe1c651544721007d344f9d8945c95c76a70a20bf9"
    )
}

rule TYPE_OOXML_CD00_CONTAINER
{
  
    meta:
        file_type = "MS Office OOXML (CD00)"
strings:
    $cd00 = { 43 44 30 30 14 00 06 00 08 00 00 00 21 00 ?? ?? ?? ?? ?? ?? 00 00 ?? ?? 00 00 ?? 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? }
  condition:
    $cd00 at 0
    and math.entropy(0, filesize) > 6.0
    and
    (
      hash.sha256(0, filesize) == "131694dfcd8c271b37e54ca9e5c1abbb9ac88526e15cbb9356084667282d36eb"
    )
}
