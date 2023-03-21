#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libunwind.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <errno.h>

#include "shuffle.h"

/* Get by the python script */
const int N = 689;
int main_offset = 0x107a9;
int num[] = {1, 2, 3, 4, 5, 6, 7, 10, 15, 20, 22, 23, 25, 26, 27, 28, 30, 33, 38, 43, 44, 45, 47, 48, 50, 56, 57, 58, 61, 62, 67, 70, 71, 73, 75, 76, 77, 81, 84, 87, 92, 95, 96, 97, 101, 102, 108, 109, 111, 112, 113, 114, 115, 117, 120, 124, 126, 129, 132, 133, 134, 139, 141, 142, 144, 145, 147, 149, 152, 153, 154, 155, 157, 158, 159, 160, 163, 164, 167, 169, 171, 173, 175, 176, 179, 180, 182, 183, 185, 186, 189, 199, 200, 201, 203, 206, 208, 212, 218, 220, 221, 222, 224, 226, 230, 234, 235, 238, 239, 240, 242, 244, 248, 249, 254, 257, 259, 260, 261, 262, 265, 269, 271, 272, 273, 278, 280, 283, 284, 285, 286, 287, 290, 291, 293, 299, 300, 304, 307, 311, 313, 315, 317, 318, 320, 321, 326, 328, 329, 330, 331, 332, 333, 334, 337, 338, 339, 340, 351, 355, 360, 366, 367, 368, 369, 374, 375, 377, 380, 391, 396, 403, 406, 407, 408, 409, 411, 412, 413, 415, 416, 418, 421, 424, 427, 429, 430, 432, 433, 437, 439, 440, 443, 446, 448, 450, 451, 457, 460, 461, 466, 467, 469, 470, 473, 480, 482, 489, 492, 497, 498, 499, 501, 502, 505, 508, 509, 511, 512, 513, 518, 519, 520, 523, 527, 528, 529, 531, 532, 533, 534, 537, 538, 539, 541, 543, 545, 546, 548, 550, 551, 556, 557, 558, 561, 562, 563, 566, 567, 568, 569, 571, 572, 573, 574, 575, 576, 577, 581, 583, 584, 590, 591, 597, 598, 601, 606, 607, 609, 613, 620, 621, 624, 628, 629, 630, 631, 632, 634, 635, 636, 637, 639, 641, 642, 646, 648, 650, 651, 657, 659, 660, 661, 662, 663, 674, 676, 677, 680, 683, 684, 685, 687, 688, 692, 697, 698, 699, 701, 704, 706, 707, 709, 710, 711, 712, 716, 717, 718, 719, 720, 726, 728, 729, 738, 739, 741, 744, 748, 751, 753, 754, 756, 757, 758, 760, 761, 762, 764, 766, 769, 771, 772, 775, 776, 777, 779, 782, 783, 785, 786, 787, 788, 794, 796, 797, 799, 800, 801, 805, 807, 808, 811, 814, 816, 817, 822, 823, 825, 827, 828, 829, 834, 841, 842, 847, 849, 850, 851, 852, 853, 854, 855, 856, 857, 860, 862, 864, 865, 866, 870, 871, 872, 873, 876, 877, 884, 885, 891, 892, 893, 894, 896, 897, 898, 900, 901, 902, 903, 906, 908, 919, 920, 921, 924, 925, 927, 929, 930, 932, 933, 936, 943, 944, 945, 946, 947, 949, 950, 952, 953, 954, 956, 960, 961, 963, 969, 970, 971, 974, 977, 981, 983, 985, 986, 988, 989, 990, 993, 995, 999, 1001, 1004, 1007, 1008, 1011, 1012, 1013, 1015, 1016, 1019, 1021, 1023, 1026, 1027, 1032, 1034, 1035, 1040, 1045, 1049, 1051, 1055, 1056, 1059, 1063, 1064, 1067, 1068, 1069, 1071, 1072, 1073, 1074, 1082, 1084, 1085, 1090, 1093, 1095, 1097, 1098, 1099, 1101, 1103, 1105, 1106, 1107, 1110, 1111, 1114, 1115, 1116, 1117, 1120, 1121, 1125, 1126, 1128, 1129, 1132, 1133, 1134, 1136, 1137, 1140, 1142, 1143, 1144, 1147, 1148, 1149, 1151, 1152, 1156, 1160, 1163, 1165, 1166, 1167, 1169, 1175, 1176, 1179, 1180, 1182, 1184, 1185, 1186, 1188, 1189, 1191, 1192, 1193, 1194, 1198, 1200, 1202, 1203, 1204, 1206, 1208, 1211, 1212, 1213, 1215, 1217, 1218, 1219, 1221, 1225, 1226, 1229, 1230, 1231, 1232, 1234, 1235, 1237, 1239, 1242, 1243, 1246, 1247, 1250, 1251, 1253, 1254, 1255, 1256, 1258, 1259, 1260, 1263, 1264, 1266, 1268, 1269, 1272, 1273, 1276, 1279, 1280, 1282, 1283, 1284, 1285, 1287, 1291, 1293, 1300, 1304, 1306, 1308, 1309, 1310, 1312, 1313, 1316, 1317, 1318, 1321, 1324, 1326, 1331, 1332, 1333, 1335, 1337, 1338, 1342, 1345, 1346, 1347, 1348, 1351, 1353, 1354, 1355, 1356, 1359, 1360, 1361, 1362, 1363, 1365, 1368, 1370, 1373, 1374, 1377, 1379, 1380, 1385, 1386, 1388, 1390, 1391, 1394, 1395, 1396, 1398, 1399, 1400, 1401, 1406, 1407, 1409, 1413, 1414, 1415, 1418, 1419, 1421, 1422, 1423, 1424, 1426, 1433, 1434, 1436, 1437, 1445, 1446, 1448, 1450, 1451, 1454, 1457, 1461, 1463, 1464, 1467, 1468, 1469, 1471, 1473, 1475, 1476};
char got_offset[][10] = {"18b30", "180c0", "18b40", "18048", "18ae8", "18300", "18db0", "17b98", "18618", "17e08", "17e10", "188c8", "18868", "17da0", "188b8", "17d98", "18b78", "180d8", "18af8", "18390", "18e58", "18368", "182d0", "18d90", "185f0", "18648", "17b68", "185c8", "17f48", "189e0", "17f08", "18200", "18c90", "18c60", "18c70", "181d8", "18bf8", "18fa8", "184c8", "18f28", "17ce0", "18730", "17c58", "18710", "18820", "17d58", "17c98", "18758", "189d0", "17f30", "189c8", "17f18", "18998", "18970", "18d20", "18c48", "18c20", "181b0", "18f70", "184a8", "18f50", "184e8", "17c80", "18750", "18740", "17cf8", "17cc8", "17d10", "189b0", "17f10", "18988", "17ef8", "17ed8", "18a10", "17f70", "181f0", "18c18", "181c8", "18cc0", "18ca0", "18fc0", "18fb0", "17a40", "18538", "18f40", "17c70", "17cf0", "18798", "18780", "17d18", "187b0", "18a38", "17b30", "18620", "18608", "17a90", "17a78", "18df0", "18d10", "18088", "18b10", "18060", "17fc8", "17fb8", "17de8", "17d50", "18800", "17d30", "18848", "18600", "18588", "18578", "18558", "17a60", "18268", "18d58", "18d30", "18a70", "17fb0", "18a60", "18008", "18038", "17d60", "18810", "17d48", "18840", "17a80", "18570", "17a70", "18550", "17a58", "185b0", "18d08", "182c0", "182a8", "18260", "17bc0", "17bd8", "18610", "17e80", "17e78", "17de0", "17dd8", "188a8", "18168", "18b98", "18058", "18050", "18ae0", "18ec0", "18430", "18ea8", "18410", "18dd8", "18328", "18dd0", "18320", "186c0", "18920", "188b0", "18af0", "18b28", "18098", "18b08", "18080", "18318", "18e10", "18df8", "17b38", "17dd0", "188a0", "18500", "18f98", "183f8", "18ea0", "183e8", "18c58", "18208", "18ca8", "18c80", "18140", "18138", "17f50", "189e8", "17e70", "17e50", "17cd8", "17cb0", "186b0", "186a0", "18698", "184f8", "18f90", "183e0", "183d8", "18c78", "18148", "18108", "17f40", "189f0", "17e58", "18918", "18910", "186a8", "17bc8", "18e98", "18e90", "18470", "18130", "18b88", "18180", "18ba8", "18580", "17a68", "185a0", "18f80", "184d8", "17d40", "18808", "17d70", "18770", "17ca0", "18a68", "17ff0", "17f28", "189b8", "17f20", "18d38", "182b0", "18d18", "18280", "18c40", "181e0", "18c28", "17a88", "18f88", "18f78", "184c0", "184b0", "17d68", "18828", "17ca8", "18768", "17c90", "189d8", "17f38", "189c0", "17f00", "18978", "17ee0", "18a28", "18288", "18c68", "181f8", "18c50", "181e8", "18c30", "181d0", "184b8", "184a0", "18f58", "18760", "17c88", "17cc0", "18778", "184e0", "17a30", "18528", "187d8", "18cd0", "17f78", "18a00", "17f98", "18230", "18ce8", "18790", "17d00", "187a8", "187b8", "17f90", "18a48", "17f80", "17f60", "17a38", "18520", "187c0", "187a0", "18cc8", "18220", "18530", "18510", "18a30", "18250", "18cf8", "18238", "17f88", "17f68", "18a08", "17d38", "187e0", "17d28", "187e8", "184f0", "18fc8", "18548", "18cb0", "18218", "18ce0", "185a8", "17ab8", "17ae0", "18878", "18858", "18830", "17d80", "18850", "18aa8", "18030", "18a98", "18018", "17fe0", "182f8", "182e0", "18d48", "17ad8", "18590", "17ac0", "18870", "18838", "18ab0", "18aa0", "18010", "18000", "18a78", "17fd8", "18ac0", "18028", "18d88", "18d70", "18d40", "18290", "17b20", "185d8", "17b00", "18298", "18d28", "18d50", "17da8", "18898", "18598", "17a98", "185b8", "17ab0", "18ad0", "18ad8", "18040", "17d78", "18e00", "18330", "18378", "18668", "17b60", "18b48", "180b8", "183a0", "18e20", "188d8", "180d0", "180a8", "18090", "18b20", "18068", "17e00", "17b80", "18670", "17b50", "17af8", "18b58", "180b0", "18e30", "18398", "18e28", "18388", "18e08", "18350", "18120", "180f0", "180f8", "18b80", "17df0", "18908", "17e20", "188f0", "17e28", "18628", "17b58", "17ba8", "18678", "18e88", "183c0", "18e68", "183a8", "183b0", "18b00", "18070", "18eb8", "18440", "18ed0", "18458", "17c48", "17c40", "18928", "18938", "17e98", "18bd8", "18198", "18190", "18178", "18bc0", "18f18", "18450", "18ee8", "17c50", "18700", "17c38", "186e8", "17c10", "17be0", "18990", "18960", "17ec0", "18968", "186e0", "181b8", "18be0", "18be8", "18948", "18490", "18f48", "18488", "18f30", "18748", "18728", "18738", "17c60", "18eb0", "18438", "17ed0", "186f0", "18708", "18958", "185e0", "17b08", "185d0", "17aa8", "17dc0", "18890", "17dc8", "17db8", "18880", "17d88", "18a90", "18ab8", "17fe8", "18a80", "18d68", "18d80", "182e8", "18568", "17ac8", "17eb0", "187f8", "18bb0", "18150", "18bc8", "18020", "18ac8", "17ff8", "18ee0", "18408", "18d78", "182d8", "18da0", "182a0", "17e18", "17e60", "18900", "187d0", "180e0", "18128", "18118", "18c00", "18188", "183d0", "183b8", "18380", "18e48", "18340", "181c0", "18c10", "18078", "18b18", "18508", "18fa0", "18980", "17ef0", "18228", "18c88", "18cf0", "18248", "17b70", "18658", "17b78", "17b48", "18640", "184d0", "18370", "18e38", "18338", "17ce8", "18788", "17cd0", "185e8", "17af0", "17b18", "17ec8", "18da8", "18dc8", "18308", "18db8", "18cd8", "17f58", "18a50", "17fa8", "18f60", "18f20", "17db0", "18888", "17cb8", "17d08", "187c8", "17b28", "185f8", "17b10", "18630", "18680", "18f68", "18f38", "18468", "18f08", "18ec8", "18ef0", "17c78", "186f8", "17c68", "17c28", "17bf0", "186d0", "17c18", "17e48", "17e90", "18d60", "182f0", "18110", "18b90", "180e8", "18170", "17ad0", "17aa0", "17ae8", "18460", "18f00", "18418", "18ed8", "17bd0", "18718", "18720", "17be8", "186c8", "17c08", "17fd0", "18a88", "17e30", "18d00", "18278", "18270", "182c8", "18dc0", "17a48", "18540", "17a50", "185c0", "18e60", "18e78", "187f0", "17d20", "18818", "18860", "17ba0", "17bb0", "18240", "18258", "18210", "18650", "17b40", "18a58", "18a40", "17fa0", "18a18", "18360", "18de0", "180a0", "18b68", "18b50", "18518", "17df8", "188c0", "188e8", "188d0", "17e40", "18cb8", "18638", "17b90", "18660", "17b88", "189f8", "18a20", "18358", "18de8", "18348", "18e40", "180c8", "18b60", "18100", "18b38", "18b70", "18160", "188e0", "17e68", "188f8", "17e88", "17e38", "18690", "17bb8", "186d8", "18688", "18e18", "183c8", "18e80", "18428", "18e70", "18e50", "183f0", "18310", "18d98", "182b8", "17c20", "17c00", "18930", "17eb8", "18950", "17ea0", "189a8", "17d90", "18bb8", "18158", "18ba0", "18bd0", "18ef8", "18400", "18478", "18f10", "186b8", "17bf8", "17c30", "18940", "17ea8", "189a0", "17ee8", "18c08", "18c38", "181a0", "18c98", "181a8", "18bf0", "18448", "18480", "18498", "18fb8"};
char addr_offset[][10] = {"fd84", "e8a4", "fda4", "e7b4", "fcf4", "ed24", "10284", "de54", "f354", "e334", "e344", "f8b4", "f7f4", "e264", "f894", "e254", "fe14", "e8d4", "fd14", "ee44", "103d4", "edf4", "ecc4", "10244", "f304", "f3b4", "ddf4", "f2b4", "e5b4", "fae4", "e534", "eb24", "10044", "ffe4", "10004", "ead4", "ff14", "10674", "f0b4", "10574", "e0e4", "f584", "dfd4", "f544", "f764", "e1d4", "e054", "f5d4", "fac4", "e584", "fab4", "e554", "fa54", "fa04", "10164", "ffb4", "ff64", "ea84", "10604", "f074", "105c4", "f0f4", "e024", "f5c4", "f5a4", "e114", "e0b4", "e144", "fa84", "e544", "fa34", "e514", "e4d4", "fb44", "e604", "eb04", "ff54", "eab4", "100a4", "10064", "106a4", "10684", "dba4", "f194", "105a4", "e004", "e104", "f654", "f624", "e154", "f684", "fb94", "dd84", "f364", "f334", "dc44", "dc14", "10304", "10144", "e834", "fd44", "e7e4", "e6b4", "e694", "e2f4", "e1c4", "f724", "e184", "f7b4", "f324", "f234", "f214", "f1d4", "dbe4", "ebf4", "101d4", "10184", "fc04", "e684", "fbe4", "e734", "e794", "e1e4", "f744", "e1b4", "f7a4", "dc24", "f204", "dc04", "f1c4", "dbd4", "f284", "10134", "eca4", "ec74", "ebe4", "dea4", "ded4", "f344", "e424", "e414", "e2e4", "e2d4", "f874", "e9f4", "fe54", "e7d4", "e7c4", "fce4", "104a4", "ef84", "10474", "ef44", "102d4", "ed74", "102c4", "ed64", "f4a4", "f964", "f884", "fd04", "fd74", "e854", "fd34", "e824", "ed54", "10344", "10314", "dd94", "e2c4", "f864", "f124", "10654", "ef14", "10464", "eef4", "ffd4", "eb34", "10074", "10024", "e9a4", "e994", "e5c4", "faf4", "e404", "e3c4", "e0d4", "e084", "f484", "f464", "f454", "f114", "10644", "eee4", "eed4", "10014", "e9b4", "e934", "e5a4", "fb04", "e3d4", "f954", "f944", "f474", "deb4", "10454", "10444", "f004", "e984", "fe34", "ea24", "fe74", "f224", "dbf4", "f264", "10624", "f0d4", "e1a4", "f734", "e204", "f604", "e064", "fbf4", "e704", "e574", "fa94", "e564", "10194", "ec84", "10154", "ec24", "ffa4", "eae4", "ff74", "dc34", "10634", "10614", "f0a4", "f084", "e1f4", "f774", "e074", "f5f4", "e044", "fad4", "e594", "faa4", "e524", "fa14", "e4e4", "fb74", "ec34", "fff4", "eb14", "ffc4", "eaf4", "ff84", "eac4", "f094", "f064", "105d4", "f5e4", "e034", "e0a4", "f614", "f0e4", "db84", "f174", "f6d4", "100c4", "e614", "fb24", "e654", "eb84", "100f4", "f644", "e124", "f674", "f694", "e644", "fbb4", "e624", "e5e4", "db94", "f164", "f6a4", "f664", "100b4", "eb64", "f184", "f144", "fb84", "ebc4", "10114", "eb94", "e634", "e5f4", "fb34", "e194", "f6e4", "e174", "f6f4", "f104", "106b4", "f1b4", "10084", "eb54", "100e4", "f274", "dc94", "dce4", "f814", "f7d4", "f784", "e224", "f7c4", "fc74", "e784", "fc54", "e754", "e6e4", "ed14", "ece4", "101b4", "dcd4", "f244", "dca4", "f804", "f794", "fc84", "fc64", "e744", "e724", "fc14", "e6d4", "fca4", "e774", "10234", "10204", "101a4", "ec44", "dd64", "f2d4", "dd24", "ec54", "10174", "101c4", "e274", "f854", "f254", "dc54", "f294", "dc84", "fcc4", "fcd4", "e7a4", "e214", "10324", "ed84", "ee14", "f3f4", "dde4", "fdb4", "e894", "ee64", "10364", "f8d4", "e8c4", "e874", "e844", "fd64", "e7f4", "e324", "de24", "f404", "ddc4", "dd14", "fdd4", "e884", "10384", "ee54", "10374", "ee34", "10334", "edc4", "e964", "e904", "e914", "fe24", "e304", "f934", "e364", "f904", "e374", "f374", "ddd4", "de74", "f414", "10434", "eea4", "103f4", "ee74", "ee84", "fd24", "e804", "10494", "efa4", "104c4", "efd4", "dfb4", "dfa4", "f974", "f994", "e454", "fed4", "ea54", "ea44", "ea14", "fea4", "10554", "efc4", "104f4", "dfc4", "f524", "df94", "f4f4", "df44", "dee4", "fa44", "f9e4", "e4a4", "f9f4", "f4e4", "ea94", "fee4", "fef4", "f9b4", "f044", "105b4", "f034", "10584", "f5b4", "f574", "f594", "dfe4", "10484", "ef94", "e4c4", "f504", "f534", "f9d4", "f2e4", "dd34", "f2c4", "dc74", "e2a4", "f844", "e2b4", "e294", "f824", "e234", "fc44", "fc94", "e6f4", "fc24", "101f4", "10224", "ecf4", "f1f4", "dcb4", "e484", "f714", "fe84", "e9c4", "feb4", "e764", "fcb4", "e714", "104e4", "ef34", "10214", "ecd4", "10264", "ec64", "e354", "e3e4", "f924", "f6c4", "e8e4", "e974", "e954", "ff24", "ea34", "eec4", "ee94", "ee24", "103b4", "eda4", "eaa4", "ff44", "e814", "fd54", "f134", "10664", "fa24", "e504", "eb74", "10034", "10104", "ebb4", "de04", "f3d4", "de14", "ddb4", "f3a4", "f0c4", "ee04", "10394", "ed94", "e0f4", "f634", "e0c4", "f2f4", "dd04", "dd54", "e4b4", "10274", "102b4", "ed34", "10294", "100d4", "e5d4", "fbc4", "e674", "105e4", "10564", "e284", "f834", "e094", "e134", "f6b4", "dd74", "f314", "dd44", "f384", "f424", "105f4", "10594", "eff4", "10534", "104b4", "10504", "e014", "f514", "dff4", "df74", "df04", "f4c4", "df54", "e3b4", "e444", "101e4", "ed04", "e944", "fe44", "e8f4", "ea04", "dcc4", "dc64", "dcf4", "efe4", "10524", "ef54", "104d4", "dec4", "f554", "f564", "def4", "f4b4", "df34", "e6c4", "fc34", "e384", "10124", "ec14", "ec04", "ecb4", "102a4", "dbb4", "f1a4", "dbc4", "f2a4", "103e4", "10414", "f704", "e164", "f754", "f7e4", "de64", "de84", "eba4", "ebd4", "eb44", "f3c4", "dda4", "fbd4", "fba4", "e664", "fb54", "ede4", "102e4", "e864", "fdf4", "fdc4", "f154", "e314", "f8a4", "f8f4", "f8c4", "e3a4", "10094", "f394", "de44", "f3e4", "de34", "fb14", "fb64", "edd4", "102f4", "edb4", "103a4", "e8b4", "fde4", "e924", "fd94", "fe04", "e9e4", "f8e4", "e3f4", "f914", "e434", "e394", "f444", "de94", "f4d4", "f434", "10354", "eeb4", "10424", "ef74", "10404", "103c4", "ef04", "ed44", "10254", "ec94", "df64", "df24", "f984", "e494", "f9c4", "e464", "fa74", "e244", "fe94", "e9d4", "fe64", "fec4", "10514", "ef24", "f014", "10544", "f494", "df14", "df84", "f9a4", "e474", "fa64", "e4f4", "ff34", "ff94", "ea64", "10054", "ea74", "ff04", "efb4", "f024", "f054", "10694"};

int init()
{
    int fd, sz;
    char buf[16384], *s = buf;
    if ((fd = open("/proc/self/maps", O_RDONLY)) < 0) printf("1");
    while ((sz = read(fd, s, sizeof(buf) - 1 - (s - buf))) > 0){ s += sz; }
    *s = 0;
    s = buf;
    close(fd);

    //for (int i = 0; i < 1000; i++) printf("%c", buf[i]);
    //printf("\n");

    char base_str[16];
    strncpy(base_str, buf, 12);
    unsigned long int base = strtol(base_str, NULL, 16);
    //printf("%lx\n", base);

    void *handle = dlopen("libpoem.so", RTLD_LAZY);
    if (handle == NULL) printf("3");

    int mapping[1477];
    for (int i = 0; i < 1477; i++){
        mapping[ndat[i]] = i;
    }

    int PageSize = sysconf(_SC_PAGE_SIZE);
    
    for (int i = 0; i < N; i++){
        // Find the address needed to be writen
        unsigned long int got_off = strtol(got_offset[i], NULL, 16);
        unsigned long int addr = base + got_off;
        // printf("%lx %lx %lx\n", base, got_off, addr);

        // Find where the actual function is
        int target_num = mapping[num[i]];
        char target_num_str[8];
        char target_str[16] = "code_";
        sprintf(target_num_str, "%d", target_num);
        strcat(target_str, target_num_str);
        void *ptr = dlsym(handle, target_str);
        // printf("%d %d %s %s\n", code_num[i], target_num, target_num_str, target_str);
        // printf("%s %p\n", target_str, ptr);

        // change old function address to a new one
        void *a = (void *)(addr & ~(PageSize - 1));
        if (mprotect(a, PageSize, PROT_READ | PROT_WRITE | PROT_EXEC) == -1){
            printf("error = %s\n", strerror(errno));
        }
        memcpy((void*)addr, &ptr, 8);
    }
}