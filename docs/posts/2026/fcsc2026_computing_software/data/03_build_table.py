# from self modifying script

TABLE = [None, None, None, None, None, None, 245, 160, 165, None, None, 243, None, 166, None, 163, 169, None, None, None, 247, None, 161, 247, 160, None, None, None, 167, 163, None, 240, 163, 245, None, 165, None, None, 168, 164, None, None, None, None, None, 243, None, None, 165, None, None, None, None, 165, 245, None, None, None, None, 162, None, 242, None, None, None, None, 167, None, 168, 167, None, 215, None, None, None, None, 165, 245, 160, None, 160, None, None, 240, 166, 165, None, None, 169, 247, 166, None, None, None, 247, None, 166, None, 162, None, None, None, None, 163, 245, 169, 165, 240, None, None, 164, 165, None, None, None, None, None, None, 247, None, None, 169, 242, 242, 165, 245, 169, 240]

# from triton script

TABLE[100] = 0xa3
TABLE[101] = 0xf5
TABLE[102] = 0xf0
TABLE[103] = 0xa3
TABLE[104] = 0xf5
TABLE[105] = 0xa9
TABLE[106] = 0xa5
TABLE[107] = 0xf0
TABLE[108] = 0xf0
TABLE[109] = 0xa8
TABLE[1] = 0xd2
TABLE[110] = 0xa4
TABLE[11] = 0xf3
TABLE[112] = 0xa0
TABLE[114] = 0xa2
TABLE[115] = 0xa8
TABLE[116] = 0xf3
TABLE[117] = 0xf2
TABLE[118] = 0xf7
TABLE[119] = 0xa5
TABLE[120] = 0xf2
TABLE[12] = 0xf0
TABLE[121] = 0xa9
TABLE[122] = 0xf2
TABLE[123] = 0xf2
TABLE[124] = 0xa5
TABLE[125] = 0xf5
TABLE[126] = 0xa9
TABLE[127] = 0xf0
TABLE[13] = 0xa6
TABLE[15] = 0xa3
TABLE[16] = 0xa9
TABLE[17] = 0xa9
TABLE[18] = 0xf7
TABLE[19] = 0xa6
TABLE[20] = 0xf7
TABLE[2] = 0xc2
TABLE[21] = 0xa4
TABLE[23] = 0xf7
TABLE[24] = 0xa0
TABLE[25] = 0xa6
TABLE[26] = 0xa0
TABLE[27] = 0xa2
TABLE[29] = 0xa3
TABLE[30] = 0xf5
TABLE[31] = 0xf0
TABLE[32] = 0xa3
TABLE[33] = 0xf5
TABLE[34] = 0xa9
TABLE[35] = 0xa5
TABLE[36] = 0xf0
TABLE[37] = 0xf0
TABLE[38] = 0xa8
TABLE[39] = 0xa4
TABLE[40] = 0xa5
TABLE[4] = 0xea
TABLE[41] = 0xa0
TABLE[42] = 0xa7
TABLE[43] = 0xa2
TABLE[44] = 0xa8
TABLE[45] = 0xf3
TABLE[46] = 0xf2
TABLE[47] = 0xf7
TABLE[48] = 0xa5
TABLE[5] = 0xa5
TABLE[51] = 0xf2
TABLE[52] = 0xf2
TABLE[53] = 0xa5
TABLE[55] = 0xa9
TABLE[56] = 0xf0
TABLE[57] = 0xa5
TABLE[58] = 0xa7
TABLE[59] = 0xa2
TABLE[60] = 0xa8
TABLE[6] = 0xf5
TABLE[61] = 0xf2
TABLE[62] = 0xf4
TABLE[63] = 0xa6
TABLE[64] = 0xa3
TABLE[65] = 0xf0
TABLE[69] = 0xa7
TABLE[70] = 0xec
TABLE[7] = 0xa0
TABLE[71] = 0xd7
TABLE[73] = 0xc2
TABLE[74] = 0xd2
TABLE[75] = 0xea
TABLE[76] = 0xa5
TABLE[77] = 0xf5
TABLE[78] = 0xa0
TABLE[79] = 0xa5
TABLE[80] = 0xa0
TABLE[81] = 0xa2
TABLE[82] = 0xf3
TABLE[83] = 0xf0
TABLE[84] = 0xa6
TABLE[85] = 0xa5
TABLE[86] = 0xa3
TABLE[87] = 0xa9
TABLE[89] = 0xf7
TABLE[90] = 0xa6
TABLE[9] = 0xa0
TABLE[91] = 0xf7
TABLE[94] = 0xf7
TABLE[98] = 0xa2




for n, c in enumerate(TABLE):
    if c is None:
        TABLE[n] = ord("_")
    else:
        TABLE[n] ^=  0x91

print(bytes(TABLE))
