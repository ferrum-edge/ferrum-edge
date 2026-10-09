// Test the actual loader validator against synthetic BTF, without root or BPF.
#define main observer_runtime_main
#include "observer.c"
#undef main
#include <assert.h>

static void bind_case(const char *socket_name, const char *address_name,
                      bool address_pointer, int length_size, int return_size,
                      int argc, int expected)
{
    struct btf *b = btf__new_empty();
    assert(!libbpf_get_error(b));
    int socket = btf__add_struct(b, socket_name, 0);
    assert(socket > 0);
    int socket_ptr = btf__add_ptr(b, socket);
    assert(socket_ptr > 0);
    int address = btf__add_struct(b, address_name, 0);
    assert(address > 0);
    if (address_pointer) address = btf__add_ptr(b, address);
    assert(address > 0);
    int length = btf__add_int(b, "length", length_size, BTF_INT_SIGNED);
    int ret = btf__add_int(b, "return_value", return_size, BTF_INT_SIGNED);
    assert(length > 0 && ret > 0);
    int proto = btf__add_func_proto(b, ret);
    assert(proto > 0);
    assert(!btf__add_func_param(b, "sock", socket_ptr));
    assert(!btf__add_func_param(b, "addr", address));
    assert(!btf__add_func_param(b, "len", length));
    if (argc == 4) assert(!btf__add_func_param(b, "extra", length));
    assert(btf__add_func(b, "inet_bind", BTF_FUNC_GLOBAL, proto) > 0);
    assert(check_site(b, &lifetime_sites[1]) == expected);
    assert(check_site(b, &classic_sites[3]) == expected);
    btf__free(b);
}

int main(void)
{
    bind_case("socket", "sockaddr", true, 4, 4, 3, 0);
    bind_case("socket", "sockaddr_unsized", true, 4, 4, 3, 0);
    bind_case("socket", "sockaddr_storage", true, 4, 4, 3, EPROTO);
    bind_case("socket", "sockaddr_unsized", false, 4, 4, 3, EPROTO);
    bind_case("wrong_socket", "sockaddr_unsized", true, 4, 4, 3, EPROTO);
    bind_case("socket", "sockaddr_unsized", true, 8, 4, 3, EPROTO);
    bind_case("socket", "sockaddr_unsized", true, 4, 8, 3, EPROTO);
    bind_case("socket", "sockaddr_unsized", true, 4, 4, 4, EPROTO);
    puts("ok: inet_bind BTF prototype regression tests passed");
    return 0;
}
