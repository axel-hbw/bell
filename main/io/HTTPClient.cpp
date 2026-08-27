#include "HTTPClient.h"

#include <string.h>   // for memcpy
#include <algorithm>  // for transform
#include <cassert>    // for assert
#include <cctype>     // for tolower
#include <ostream>    // for operator<<, basic_ostream
#include <stdexcept>  // for runtime_error

#include "BellSocket.h"  // for bell

using namespace bell;

void HTTPClient::Response::connect(const std::string& url) {
  urlParser = bell::URLParser::parse(url);

  // Open socket of type
  this->socketStream.open(urlParser.host, urlParser.port,
                          urlParser.schema == "https");
}

HTTPClient::Response::~Response() {
  if (this->socketStream.isOpen()) {
    this->socketStream.close();
  }
}

void HTTPClient::Response::rawRequest(const std::string& url,
                                      const std::string& method,
                                      const std::vector<uint8_t>& content,
                                      Headers& headers) {
  urlParser = bell::URLParser::parse(url);

  // Prepare a request
  const char* reqEnd = "\r\n";

  // Jukebox-fix: this Response reuses one keep-alive socket across requests
  // (CDNAudioFile issues header -> footer -> many range reads on it). Spotify's
  // CDN drops idle keep-alive sockets, notably during the ~5 s Connect
  // handshake before the first data read. Writing into that dead socket makes
  // readResponseHeaders() see zero bytes and throw "closed before response
  // headers" -> the track ends without a note (see CDNAudioFile catch).
  // Reopen a fresh socket and replay the request once before giving up. GETs
  // are idempotent and a zero-response POST never reached the peer, so a single
  // retry is safe. Bounded to one retry so a genuinely unreachable host still
  // surfaces the error instead of spinning.
  for (int attempt = 0;; attempt++) {
    try {
      socketStream << method << " " << urlParser.path << " HTTP/1.1" << reqEnd;
      socketStream << "Host: " << urlParser.host << ":" << urlParser.port
                   << reqEnd;
      socketStream << "Connection: keep-alive" << reqEnd;
      socketStream << "Accept: */*" << reqEnd;

      // Write content
      if (content.size() > 0) {
        socketStream << "Content-Length: " << content.size() << reqEnd;
      }

      // Write headers
      for (auto& header : headers) {
        socketStream << header.first << ": " << header.second << reqEnd;
      }

      socketStream << reqEnd;

      // Write request body
      if (content.size() > 0) {
        socketStream.write((const char*)content.data(), content.size());
      }

      socketStream.flush();

      // Parse response
      readResponseHeaders();
      return;
    } catch (const std::exception& e) {
      if (attempt >= 1) {
        throw;
      }
      // The failed read left failbit set on the shared iostream, which would
      // make the replayed request's writes no-ops. Clear it, then open a fresh
      // socket (open() also resets the streambuf, dropping any bytes the failed
      // request left half-written) before replaying.
      this->connect(url);
      socketStream.clear();
    }
  }
}

void HTTPClient::Response::readResponseHeaders() {
  char *method, *path;
  const char* msgPointer;

  size_t msgLen;
  int pret, minorVersion, status;

  size_t prevbuflen = 0, numHeaders;
  this->httpBufferAvailable = 0;

  while (1) {
    socketStream.getline((char*)httpBuffer.data() + httpBufferAvailable,
                         httpBuffer.size() - httpBufferAvailable);

    prevbuflen = httpBufferAvailable;
    httpBufferAvailable += socketStream.gcount();

    // Jukebox-fix: a closed/reset keep-alive socket makes getline() extract
    // zero bytes and set failbit. The original loop then spun forever
    // (phr_parse_response keeps returning -2 because the buffer never grows),
    // pinning the CPU and starving the idle task -> task_wdt on cspot_player.
    // A truncated read that finds no delimiter fills the buffer (gcount > 0)
    // and is caught by the "Response too large" check below, so gcount == 0
    // reliably means the peer went away before the headers arrived.
    if (socketStream.gcount() == 0) {
      throw std::runtime_error("HTTP connection closed before response headers");
    }

    // Restore delimiters
    memcpy(httpBuffer.data() + httpBufferAvailable - 2, "\r\n", 2);

    // Parse the request
    numHeaders = sizeof(phResponseHeaders) / sizeof(phResponseHeaders[0]);

    pret =
        phr_parse_response((const char*)httpBuffer.data(), httpBufferAvailable,
                           &minorVersion, &status, &msgPointer, &msgLen,
                           phResponseHeaders, &numHeaders, prevbuflen);

    if (pret > 0) {
      break; /* successfully parsed the request */
    } else if (pret == -1)
      throw std::runtime_error("Cannot parse http response");

    /* request is incomplete, continue the loop */
    assert(pret == -2);
    if (httpBufferAvailable == httpBuffer.size())
      throw std::runtime_error("Response too large");
  }

  this->responseHeaders = {};

  // Headers have benen read
  for (int headerIndex = 0; headerIndex < numHeaders; headerIndex++) {
    this->responseHeaders.push_back(
        ValueHeader{std::string(phResponseHeaders[headerIndex].name,
                                phResponseHeaders[headerIndex].name_len),
                    std::string(phResponseHeaders[headerIndex].value,
                                phResponseHeaders[headerIndex].value_len)});
  }

  std::string contentLengthValue = std::string(header("content-length"));
  if (contentLengthValue.size() > 0) {
    this->hasContentSize = true;
    this->contentSize = std::stoi(contentLengthValue);
  }
}

void HTTPClient::Response::get(const std::string& url, Headers headers) {
  std::string method = "GET";
  return this->rawRequest(url, method, {}, headers);
}

void HTTPClient::Response::post(const std::string& url, Headers headers,
                                const std::vector<uint8_t>& body) {
  std::string method = "POST";
  return this->rawRequest(url, method, body, headers);
}

size_t HTTPClient::Response::contentLength() {
  return contentSize;
}

std::string_view HTTPClient::Response::header(const std::string& headerName) {
  for (auto& header : this->responseHeaders) {
    std::string headerValue = header.first;
    std::transform(headerValue.begin(), headerValue.end(), headerValue.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    if (headerName == headerValue) {
      return header.second;
    }
  }

  return "";
}

size_t HTTPClient::Response::totalLength() {
  auto rangeHeader = header("content-range");

  if (rangeHeader.find("/") != std::string::npos) {
    return std::stoi(
        std::string(rangeHeader.substr(rangeHeader.find("/") + 1)));
  }

  return this->contentLength();
}

void HTTPClient::Response::readRawBody() {
  if (contentSize > 0 && rawBody.size() == 0) {
    rawBody = std::vector<uint8_t>(contentSize);
    socketStream.read((char*)rawBody.data(), contentSize);
  }
}

std::string_view HTTPClient::Response::body() {
  readRawBody();
  return std::string_view((char*)rawBody.data(), rawBody.size());
}

std::vector<uint8_t> HTTPClient::Response::bytes() {
  readRawBody();
  return rawBody;
}
