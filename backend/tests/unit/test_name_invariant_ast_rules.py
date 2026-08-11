"""Paired name-mutation checks for structurally decidable LEA rules.

These tests do not encode corpus labels.  They hold the program structure fixed
and change only non-normative identifiers, guarding against answer-cue routing.
"""


def test_lea031_wrong_arx_order_is_invariant_to_function_and_symbol_names(check_rule):
    named = """
typedef unsigned int uint32_t;
uint32_t ROL9(uint32_t, int);
void lea_encrypt(uint32_t *state, const uint32_t *round_key) {
    uint32_t a,b,c,d;
    a = ROL9(b ^ (c + round_key[0]), 9);
    b = ROL9(c ^ (d + round_key[1]), 5);
}
"""
    opaque = (named.replace("lea_encrypt", "f_7")
              .replace("state", "p_0")
              .replace("round_key", "p_1")
              .replace("ROL9", "rotate_7"))
    named_result = check_rule("LEA-031", named, filename="lea_enc.c")
    opaque_result = check_rule(
        "LEA-031", opaque, filename="unit_7.c",
        symbol_graph={"experimental_name_invariant_routing": True},
    )
    assert len(named_result) == len(opaque_result) == 2


def test_lea022_modulo8_schedule_is_invariant_to_function_and_array_names(check_rule):
    named = """
typedef unsigned int uint32_t;
uint32_t ROL32(uint32_t, int);
void lea_set_key(uint32_t *rk) {
    uint32_t T[8]; int i, j;
    for (i=0;i<32;i++) for(j=0;j<6;j++)
        T[(6*i+j)%8] = ROL32(T[(6*i+j)%8] + i, j);
}
"""
    opaque = (named.replace("lea_set_key", "f_9")
              .replace("T[", "q[")
              .replace("uint32_t T[8]", "uint32_t q[8]")
              .replace("ROL32", "rotate_9"))
    assert check_rule("LEA-022", named, filename="lea_key.c") == []
    assert check_rule(
        "LEA-022", opaque, filename="unit_9.c",
        symbol_graph={"experimental_name_invariant_routing": True},
    ) == []


def test_lea022_missing_modulo_is_invariant_to_function_and_array_names(check_rule):
    named = """
typedef unsigned int uint32_t;
void lea_set_key(uint32_t *rk) {
    uint32_t T[8]; int i, j;
    for (i=0;i<32;i++) for(j=0;j<6;j++) T[6*i+j] = T[i] + j;
}
"""
    opaque = (named.replace("lea_set_key", "f_11")
              .replace("T[", "q[")
              .replace("uint32_t T[8]", "uint32_t q[8]"))
    assert len(check_rule("LEA-022", named, filename="lea_key.c")) == 1
    assert len(check_rule(
        "LEA-022", opaque, filename="unit_11.c",
        symbol_graph={"experimental_name_invariant_routing": True},
    )) == 1


def test_generic_arithmetic_helper_is_not_misclassified_as_lea_round(check_rule):
    code = """
unsigned helper(unsigned a, unsigned b) {
    return (a ^ (b + 1)) << 2;
}
"""
    assert check_rule("LEA-031", code, filename="utility.c") == []


def test_arbitrary_rotate_helper_does_not_enable_production_routing(check_rule):
    code = """
typedef unsigned int u32;
u32 q(u32, int);
void f(u32 *a, u32 *b) {
    u32 x,y,z,w;
    x=q(y^(z+b[0]),9); y=q(z^(w+b[1]),5);
}
"""
    assert check_rule("LEA-031", code, filename="opaque.c") == []


def test_temporary_ordering_is_conservatively_unresolved(check_rule):
    code = """
typedef unsigned int u32;
u32 rot(u32, int);
void lea_encrypt(u32 *a, u32 *b) {
    u32 x,y,z,w,t0,t1;
    t0=z+b[0]; x=rot(y^t0,9); t1=w+b[1]; y=rot(z^t1,5);
}
"""
    assert check_rule("LEA-031", code, filename="lea.c") == []


def test_non_lea_inline_arx_is_not_production_routed(check_rule):
    code = """
typedef unsigned int u32;
void checksum(u32 *a, u32 *b) {
    u32 x,y,z,w;
    x=((y^(z+b[0]))<<9)|((y^(z+b[0]))>>23);
    y=((z^(w+b[1]))<<5)|((z^(w+b[1]))>>27);
}
"""
    assert check_rule("LEA-031", code, filename="checksum.c") == []


def test_lea022_accepts_bitmask_modulo_for_unsigned_index(check_rule):
    code = """
typedef unsigned int u32;
void lea_set_key(u32 *rk) {
    u32 T[8]; int i,j;
    for(i=0;i<32;i++) for(j=0;j<6;j++) T[(6*i+j)&7] += j;
}
"""
    assert check_rule("LEA-022", code, filename="lea.c") == []


def test_lea022_rejects_wrong_multiplier_even_with_modulo(check_rule):
    code = """
typedef unsigned int u32;
void lea_set_key(u32 *rk) {
    u32 T[8]; int i,j;
    for(i=0;i<32;i++) for(j=0;j<6;j++) T[(4*i+j)%8] += j;
}
"""
    assert len(check_rule("LEA-022", code, filename="lea.c")) == 1


def test_lea022_follows_named_ks256_index_temporary(check_rule):
    code = """
typedef unsigned int u32;
void ks256(u32 *rk) {
    u32 T[8]; int i,j,idx;
    for(i=0;i<32;i++) for(j=0;j<6;j++) {
        idx=(4*i+j)%8; rk[6*i+j]=T[idx];
    }
}
"""
    assert len(check_rule("LEA-022", code, filename="lea.c")) == 1


def test_lea022_does_not_apply_to_lea192_six_word_schedule(check_rule):
    code = """
typedef unsigned int u32;
void lea_set_key192(u32 *rk) {
    u32 T[6]; int i,j;
    for(i=0;i<28;i++) for(j=0;j<6;j++) T[j] += i;
}
"""
    assert check_rule("LEA-022", code, filename="lea.c") == []


def test_lea022_non_lea_histogram_is_not_production_routed(check_rule):
    code = """
void histogram(int *out) {
    int q[8]; int i;
    for(i=0;i<32;i++) out[i*6]=q[i&7];
}
"""
    assert check_rule("LEA-022", code, filename="stats.c") == []


def test_unrolled_cpp_and_macro_forms_remain_conservative(check_rule):
    unrolled = """
typedef unsigned int u32;
void lea_set_key(u32 *rk) { u32 T[8]; T[0]=1; T[1]=2; }
"""
    cpp = "#include <array>\nvoid f(){std::array<unsigned,8> q{};}"
    macro = "#define R(x,n) (((x)<<(n))|((x)>>(32-(n))))\n"
    macro += "void lea_encrypt(unsigned*a,unsigned*b){a[0]=R(a[1]^(a[2]+b[0]),9);}"
    assert check_rule("LEA-022", unrolled, filename="lea.c") == []
    assert check_rule("LEA-022", cpp, filename="opaque.cpp") is None
    assert check_rule("LEA-031", macro, filename="lea.c") in (None, [])
