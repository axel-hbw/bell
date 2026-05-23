#include "TLSSocket.h"

#include <mbedtls/ctr_drbg.h>     // for mbedtls_ctr_drbg_free, mbedtls_ctr_...
#include <mbedtls/entropy.h>      // for mbedtls_entropy_free, mbedtls_entro...
#include <mbedtls/error.h>        // Jukebox-fix: mbedtls_strerror for readable errors
#include <mbedtls/net_sockets.h>  // for mbedtls_net_connect, mbedtls_net_free
#include <mbedtls/ssl.h>          // for mbedtls_ssl_conf_authmode, mbedtls_...
#include <cstring>                // for strlen, NULL
#include <stdexcept>              // for runtime_error

#include "BellLogger.h"  // for AbstractLogger, BELL_LOG
#include "X509Bundle.h"  // for shouldVerify, attach

/**
 * Platform TLSSocket implementation for the mbedtls
 */
bell::TLSSocket::TLSSocket() {
  this->isClosed = false;
  mbedtls_net_init(&server_fd);
  mbedtls_ssl_init(&ssl);
  mbedtls_ssl_config_init(&conf);

  // Jukebox-fix: X509Bundle::attach() was here, but mbedtls requires
  // ssl_config_defaults() to run first. Moved into open() after defaults.

  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  const char* pers = "euphonium";
  int ret;
  if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                   (const unsigned char*)pers, strlen(pers))) !=
      0) {
    BELL_LOG(error, "http_tls",
             "failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
    throw std::runtime_error("mbedtls_ctr_drbg_seed failed");
  }
}

void bell::TLSSocket::open(const std::string& hostUrl, uint16_t port) {
  int ret;
  char err_buf[128];

  if ((ret = mbedtls_net_connect(&server_fd, hostUrl.c_str(),
                                 std::to_string(port).c_str(),
                                 MBEDTLS_NET_PROTO_TCP)) != 0) {
    // Jukebox-fix: was silently continuing — caused hangs deep in handshake.
    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    BELL_LOG(error, "http_tls", "mbedtls_net_connect %s:%u failed: -0x%04x %s",
             hostUrl.c_str(), port, -ret, err_buf);
    throw std::runtime_error("mbedtls_net_connect failed");
  }

  if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {

    mbedtls_strerror(ret, err_buf, sizeof(err_buf));
    BELL_LOG(error, "http_tls", "ssl_config_defaults failed: -0x%04x %s",
             -ret, err_buf);
    throw std::runtime_error("mbedtls_ssl_config_defaults failed");
  }

  // Only verify if the X509 bundle is present
  if (bell::X509Bundle::shouldVerify()) {
    // Jukebox-fix: attach the cert bundle HERE, after ssl_config_defaults.
    // Previously called in the constructor against an uninitialised config.
    bell::X509Bundle::attach(&conf);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
  } else {
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
  }

  mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

  // Jukebox-fix: bound read time so a stalled peer can't hang the task.
  mbedtls_ssl_conf_read_timeout(&conf, 15000);  // 15 s

  mbedtls_ssl_setup(&ssl, &conf);

  if ((ret = mbedtls_ssl_set_hostname(&ssl, hostUrl.c_str())) != 0) {
    throw std::runtime_error("mbedtls_ssl_set_hostname failed");
  }
  // Jukebox-fix: use the timeout-aware recv so conf_read_timeout takes effect.
  mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, NULL,
                      mbedtls_net_recv_timeout);

  while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
    if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
      mbedtls_strerror(ret, err_buf, sizeof(err_buf));
      BELL_LOG(error, "http_tls", "ssl_handshake failed: -0x%04x %s",
               -ret, err_buf);
      throw std::runtime_error("mbedtls_ssl_handshake error");
    }
  }
}

size_t bell::TLSSocket::read(uint8_t* buf, size_t len) {
  return mbedtls_ssl_read(&ssl, buf, len);
}

size_t bell::TLSSocket::write(uint8_t* buf, size_t len) {
  return mbedtls_ssl_write(&ssl, buf, len);
}

size_t bell::TLSSocket::poll() {
  return mbedtls_ssl_get_bytes_avail(&ssl);
}
bool bell::TLSSocket::isOpen() {
  return !isClosed;
}

void bell::TLSSocket::close() {
  if (!isClosed) {
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    this->isClosed = true;
  }
}
