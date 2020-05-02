import windows.generated_def as gdef

def test_format_charactere_values():
    assert gdef.FC_ZERO == 0
    assert gdef.FC_PAD == 0x5c
    assert gdef.FC_PAD == 0x5c
    assert gdef.FC_SPLIT_DEREFERENCE == 0x74
    assert gdef. FC_SPLIT_DIV_2 == 0x75
    assert gdef.FC_HARD_STRUCT  == 0xb1
    assert gdef.FC_TRANSMIT_AS_PTR   == 0xb2
    assert gdef.FC_END_OF_UNIVERSE   == 0xba