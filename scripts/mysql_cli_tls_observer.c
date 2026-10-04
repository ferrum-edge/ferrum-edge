/* Hosted qualification only. Observe the existing mysql CLI; never implement TLS I/O.
 * No verification/protocol mutation, key logging, messages, error-queue or credential APIs.
 * One numeric summary goes to privately captured stderr at normal process exit.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

typedef void (*info_callback)(const SSL *, int, int);
static SSL *(*next_new)(SSL_CTX *);
static void (*next_free)(SSL *);
static void (*set_info)(SSL *, info_callback);
static info_callback (*get_info)(const SSL *);
static info_callback (*get_ctx_info)(SSL_CTX *);
static SSL_CTX *(*get_ctx)(const SSL *);
static int (*get_fd)(const SSL *);
static int (*get_version)(const SSL *);
static int (*get_mode)(const SSL *);
static long (*get_result)(const SSL *);
static X509 *(*get_peer)(const SSL *);
static X509 *(*get_local)(const SSL *);
static void (*get_signature)(const ASN1_BIT_STRING **, const X509_ALGOR **, const X509 *);
static int (*string_length)(const ASN1_STRING *);
static const unsigned char *(*string_data)(const ASN1_STRING *);
static unsigned char server_signature[384], client_signature[384];
static unsigned server_signature_size, client_signature_size;
static uid_t material_owner;

static SSL *tracked;
static info_callback previous;
static long owner_thread;
static atomic_uint objects, invalid;
static unsigned capable, starts, done, protocol, verified, mode, peer, certificates;
static unsigned alerts, level, description, freed;
static void observe(const SSL *, int, int);

/* All resolved SSL functions must belong to the same real libssl.so.3 mapping.
 * Do not load another OpenSSL library or depend on the runner's OpenSSL ABI.
 */
static int same_library(void *symbol, void *base)
{
    Dl_info info;
    return symbol && dladdr(symbol, &info) && info.dli_fbase == base;
}

static int load_signature(const char *path, unsigned char *signature, unsigned *size)
{
    struct stat metadata;
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return 0;
    int valid = fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
                (metadata.st_mode & 0777) == 0600 && metadata.st_nlink == 1 &&
                metadata.st_uid == material_owner &&
                (metadata.st_size == 256 || metadata.st_size == 384);
    if (valid) {
        *size = (unsigned)metadata.st_size;
        valid = read(fd, signature, *size) == (ssize_t)*size;
    }
    close(fd);
    return valid;
}

__attribute__((constructor)) static void initialize(void)
{
    int saved_errno = errno;
    struct stat executable, expected, artifact;
    Dl_info library;
    void *symbol = dlsym(RTLD_NEXT, "SSL_new");
    next_new = (SSL *(*)(SSL_CTX *))symbol;
    next_free = (void (*)(SSL *))dlsym(RTLD_NEXT, "SSL_free");
    owner_thread = syscall(SYS_gettid);
    if (!symbol || !dladdr(symbol, &library) || !library.dli_fname ||
        (strcmp(library.dli_fname, "/lib64/libssl.so.3") != 0 &&
         strcmp(library.dli_fname, "/usr/lib64/libssl.so.3") != 0) ||
        stat("/proc/self/exe", &executable) || stat("/usr/bin/mysql", &expected) ||
        executable.st_dev != expected.st_dev || executable.st_ino != expected.st_ino ||
        lstat("/client/mysql-cli-tls-observer.so", &artifact) || !S_ISREG(artifact.st_mode) ||
        (artifact.st_mode & 0777) != 0600 || artifact.st_nlink != 1 ||
        artifact.st_size <= 0 || artifact.st_size > 1048576 ||
        !same_library((void *)next_free, library.dli_fbase))
        goto finish;
    material_owner = artifact.st_uid;

#define RESOLVE(target, name) do { \
    void *resolved = dlsym(RTLD_NEXT, name); \
    if (!same_library(resolved, library.dli_fbase)) goto finish; \
    target = (__typeof__(target))resolved; \
} while (0)
    RESOLVE(set_info, "SSL_set_info_callback");
    RESOLVE(get_info, "SSL_get_info_callback");
    RESOLVE(get_ctx_info, "SSL_CTX_get_info_callback");
    RESOLVE(get_ctx, "SSL_get_SSL_CTX");
    RESOLVE(get_fd, "SSL_get_fd");
    RESOLVE(get_version, "SSL_version");
    RESOLVE(get_mode, "SSL_get_verify_mode");
    RESOLVE(get_result, "SSL_get_verify_result");
    RESOLVE(get_peer, "SSL_get0_peer_certificate");
    RESOLVE(get_local, "SSL_get_certificate");
#undef RESOLVE
    symbol = dlsym(RTLD_NEXT, "X509_get0_signature");
    if (!symbol || !dladdr(symbol, &library) || !library.dli_fname ||
        (strcmp(library.dli_fname, "/lib64/libcrypto.so.3") != 0 &&
         strcmp(library.dli_fname, "/usr/lib64/libcrypto.so.3") != 0))
        goto finish;
#define RESOLVE(target, name) do { \
    void *resolved = dlsym(RTLD_NEXT, name); \
    if (!same_library(resolved, library.dli_fbase)) goto finish; \
    target = (__typeof__(target))resolved; \
} while (0)
    RESOLVE(get_signature, "X509_get0_signature");
    RESOLVE(string_length, "ASN1_STRING_length");
    RESOLVE(string_data, "ASN1_STRING_get0_data");
#undef RESOLVE
    if (!load_signature("/client/mysql-observer-server.signature", server_signature,
                        &server_signature_size) ||
        !load_signature("/client/mysql-observer-client.signature", client_signature,
                        &client_signature_size))
        goto finish;
    capable = 1;
finish:
    errno = saved_errno;
}

static unsigned certificate_matches(const X509 *certificate, const unsigned char *expected,
                                    unsigned size)
{
    const ASN1_BIT_STRING *signature = NULL;
    if (!certificate) return 0;
    get_signature(&signature, NULL, certificate);
    const unsigned char *bytes = signature ? string_data(signature) : NULL;
    return bytes && string_length(signature) == (int)size && memcmp(bytes, expected, size) == 0;
}

static int on_owner_thread(void)
{
    if (syscall(SYS_gettid) == owner_thread)
        return 1;
    atomic_store(&invalid, 1);
    return 0;
}

static void snapshot(const SSL *ssl)
{
    struct sockaddr_storage address;
    socklen_t size = sizeof(address);
    unsigned bound = 0;
    if (getpeername(get_fd(ssl), (struct sockaddr *)&address, &size) == 0) {
        if (address.ss_family == AF_INET && size == sizeof(struct sockaddr_in)) {
            const struct sockaddr_in *v4 = (const struct sockaddr_in *)&address;
            bound = v4->sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
                    v4->sin_port == htons(3306);
        } else if (address.ss_family == AF_INET6 && size == sizeof(struct sockaddr_in6)) {
            const struct sockaddr_in6 *v6 = (const struct sockaddr_in6 *)&address;
            bound = IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr) && v6->sin6_port == htons(3306);
        }
    }
    unsigned current_protocol = get_version(ssl) == TLS1_3_VERSION ? 13 : 0;
    unsigned current_verified = get_result(ssl) == X509_V_OK;
    unsigned current_mode = get_mode(ssl) == SSL_VERIFY_PEER;
    /* Read-only public accessors: compare the generated RSA certificate
     * signatures privately. Never encode X509, allocate, or touch the ERR queue
     * inside TLS, and never log certificate bytes or credential metadata.
     */
    unsigned current_certificates = certificate_matches(get_peer(ssl), server_signature,
                                                        server_signature_size) &&
                                    certificate_matches(get_local(ssl), client_signature,
                                                        client_signature_size);
    if (done && (protocol != current_protocol || verified != current_verified ||
                 mode != current_mode || peer != bound || certificates != current_certificates))
        atomic_store(&invalid, 1);
    protocol = current_protocol;
    verified = current_verified;
    mode = current_mode;
    peer = bound;
    certificates = current_certificates;
}

static void observe(const SSL *ssl, int where, int ret)
{
    int saved_errno = errno;
    /* An application context callback introduced after attachment takes priority:
     * remove our override before forwarding its current event, so even its public
     * SSL_get_info_callback view is unchanged. Never reinstall for evidence.
     */
    info_callback callback = previous ? previous : get_ctx_info(get_ctx(ssl));
    if (callback) {
        atomic_store(&invalid, 1);
        set_info((SSL *)ssl, previous);
    } else if (on_owner_thread()) {
        if (ssl != tracked || freed || get_info(ssl) != observe || callback == observe) {
            atomic_store(&invalid, 1);
        } else {
            if (where & SSL_CB_HANDSHAKE_START) {
                if (starts == 0) starts = 1;
                else atomic_store(&invalid, 1);
            }
            if (where & SSL_CB_HANDSHAKE_DONE) {
                snapshot(ssl);
                if (done == 0) done = 1;
                else atomic_store(&invalid, 1);
            }
            if ((where & SSL_CB_READ_ALERT) == SSL_CB_READ_ALERT) {
                snapshot(ssl);
                if (alerts == 0 && done == 1) {
                    alerts = 1;
                    level = ((unsigned)ret >> 8) & 255;
                    description = (unsigned)ret & 255;
                } else {
                    atomic_store(&invalid, 1);
                }
            }
            if ((where & SSL_CB_WRITE_ALERT) == SSL_CB_WRITE_ALERT &&
                (((unsigned)ret >> 8) & 255) == SSL3_AL_FATAL)
                atomic_store(&invalid, 1);
        }
    }
    errno = saved_errno;
    if (callback && callback != observe)
        callback(ssl, where, ret);
}

SSL *SSL_new(SSL_CTX *ctx)
{
    if (!next_new) _exit(126); /* Unsupported interposition; no certificate proof. */
    SSL *ssl = next_new(ctx);
    int saved_errno = errno;
    if (atomic_fetch_add(&objects, 1) != 0) atomic_store(&invalid, 1);
    if (capable && ssl && on_owner_thread() && !tracked) {
        tracked = ssl;
        previous = get_info(ssl);
        /* Preserve pre-existing callbacks exactly, including getter semantics.
         * Source metadata suggests none on this CLI, but runtime presence makes
         * this conservative observer unsupported, rather than replacing one.
         */
        if (previous || get_ctx_info(ctx)) atomic_store(&invalid, 1);
        else set_info(ssl, observe);
    }
    errno = saved_errno;
    return ssl;
}

void SSL_free(SSL *ssl)
{
    if (!next_free) _exit(126);
    int saved_errno = errno;
    if (capable && ssl && on_owner_thread() && ssl == tracked) {
        if (freed || get_info(ssl) != observe) atomic_store(&invalid, 1);
        freed = 1;
    }
    errno = saved_errno;
    next_free(ssl);
}

__attribute__((destructor)) static void summarize(void)
{
    int saved_errno = errno;
    char record[128];
    unsigned count = atomic_load(&objects);
    if (!on_owner_thread() || count != 1) atomic_store(&invalid, 1);
    int size = snprintf(record, sizeof(record),
                        "FMO1 %u %u %u %u %u %u %u %u %u %u %u %u %u %u\n",
                        capable, count > 1 ? 2 : count, starts, done, protocol,
                        verified, mode, peer, certificates, alerts, level, description,
                        freed, atomic_load(&invalid));
    /* Exactly one bounded record; no retry, formatting of strings, or raw TLS data.
     * A partial/missing record cannot pass the harness's strict parser.
     */
    if (size > 0 && (size_t)size < sizeof(record))
        (void)write(STDERR_FILENO, record, (size_t)size);
    errno = saved_errno;
}
