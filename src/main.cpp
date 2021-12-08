#include <charconv>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <thread>
#include <vector>

#include <unistd.h>
#include <fcntl.h>  /* O_RDWR */
#include <string.h> /* memset(), memcpy() */
#include <stdio.h> /* perror(), printf(), fprintf() */
#include <stdlib.h> /* exit(), malloc(), free() */
#include <sys/ioctl.h> /* ioctl() */
#include <sys/stat.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

using namespace std::string_literals;

template<typename F>
class finally {
  F f;

public:
  constexpr finally(F f) : f{f} {}
  constexpr ~finally() { f(); }
};

constexpr size_t mtu = 160;

int main(int argc, char** argv) {
  if (argc != 3)
    std::cout << argv[0] << " <address> <output>";

  int fd;
  if ((fd = open("/dev/net/tun", O_RDWR)) == -1) {
    throw std::runtime_error{"Unable to open tun driver!"};
  }
  finally fd_cleanup{[&](){ ::close(fd); }};

  struct ifreq ifr;
  std::fill(reinterpret_cast<uint8_t*>(&ifr), reinterpret_cast<uint8_t*>(&ifr) + sizeof(ifr), 0);
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  if (ioctl(fd, TUNSETIFF, (void *) &ifr) == -1) {
    throw std::runtime_error{"Unable to init tun driver!"};
  }
  if (ioctl(fd, TUNGETIFF, (void *) &ifr) == -1) {
    throw std::runtime_error{"Unable to fetch tun info!"};
  }

  ::system((std::string("ip addr add ") + argv[1] + "/8 dev " + ifr.ifr_name).c_str());
  ::system((std::string{"ip link set up dev "} + ifr.ifr_name).c_str());

  std::jthread reader_thread([&]() {
    std::ofstream output{argv[2]};
    while(true) {
      std::array<uint8_t, mtu> buf;
      size_t n_read = ::read(fd, buf.data(), buf.size());

      uint8_t ver = buf.at(0) >> 4;

      if (ver != 4)
        continue;

      std::span<uint8_t> dat{buf.data(), n_read};
      std::stringstream os;
      os << std::hex << std::setfill('0');
      size_t pos = 0;
      for (uint32_t i : dat) {
        os << std::setw(2) << std::hex << i << ' ';
        if ((++pos %= 4) == 0) {
          os << std::endl;
        }
      }
      os << std::endl;
      output << os.str() << std::endl;
    }
  });

  {
    std::string line;
    while (std::getline(std::cin, line)) {
      std::vector<uint8_t> buf;
      if (line.size() % 2 != 0)
        goto err;
      for (size_t i = 0; i < line.size(); i += 2) {
        auto& target = buf.emplace_back();
        auto res = std::from_chars(line.data() + i, line.data() + i + 2, target, 16);
        if (static_cast<int>(res.ec) != 0 || false/*(res.ptr != line.data() + i + 2)*/) {
          goto err;
        }
      }
      ::write(fd, buf.data(), buf.size());
      continue;
      err:
      std::cout << "Invalid packet!" << std::endl;
    }
  }
}
