#include <lua.h>
#include <lauxlib.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <libssh2.h>

#if LUA_VERSION_NUM < 502
  #define luaL_newlib(L, m) \
    (lua_newtable(L), luaL_register(L, NULL, m))
#endif

#define true 1
#define false 0

typedef struct {
  int socket;
  LIBSSH2_SESSION *session;
  const char *fingerprint;
} luassh_userdata_t;

static void _formatFingerprint(char *str, unsigned char *fingerprint, int length) {
  int i;
  char *f = str;
  for(i = 0; i < (length * 3); i = i + 3, ++fingerprint) {
    sprintf(&str[i], "%02X:", *fingerprint);
  }
  str[i - 1] = '\0';
}

static int _sendFile(lua_State *L, LIBSSH2_SESSION *session, char *src, char *dest, struct stat finfo) {
  FILE *fd;
  char mem[1024];
  size_t nread;
  size_t nwrote;
  char *ptr;
  LIBSSH2_CHANNEL *channel;

  channel = libssh2_scp_send(
    session, dest,
    finfo.st_mode & 0777,
    (unsigned long) finfo.st_size);

  if(!channel) {
    lua_pushnil(L);
    lua_pushstring(L, "unable to open a ssh channel");
    return 2;
  } else {
    fd = fopen(src, "rb");
    if(!fd) {
      lua_pushnil(L);
      lua_pushstring(L, "cannot read src file");
      return 2;
    } else {
      do {
        nread = fread(mem, 1, sizeof(mem), fd);
        if(nread <= 0) {
          fclose(fd);
          libssh2_channel_send_eof(channel);
          libssh2_channel_wait_eof(channel);
          libssh2_channel_wait_closed(channel);
          libssh2_channel_free(channel);
          lua_pushboolean(L, true);
          return 1;
        }
        ptr = mem;

        do {
          nwrote = libssh2_channel_write(channel, ptr, nread);
          if(nwrote < 0) {
            fclose(fd);
            libssh2_channel_send_eof(channel);
            libssh2_channel_wait_eof(channel);
            libssh2_channel_wait_closed(channel);
            libssh2_channel_free(channel);
            lua_pushnil(L);
            lua_pushstring(L, "error writing file");
            return 2;
          } else {
            ptr += nwrote;
            nread -= nwrote;
          }
        } while(nread);
      } while(1);
    }
  }
}

static int luassh_open(lua_State *L) {
  char *hostname, *port;
  struct addrinfo hints, *res, *resSave;
  luassh_userdata_t *lssh;

  hostname = (char *) luaL_checkstring(L, 1);
  if(lua_isnumber(L, 2)) {
    port = (char *) lua_tolstring(L, 2, NULL);
  } else {
    lua_pushnil(L);
    lua_pushstring(L, "second argument has to be a number");
    return 2;
  }

  if(libssh2_init(0) != 0) {
    lua_pushnil(L);
    lua_pushstring(L, "cannot initialize ssh context");
    return 2;
  } else {
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(hostname, port, &hints, &res) < 0) {
      libssh2_exit();
      lua_pushnil(L);
      lua_pushstring(L, "getaddrinfo error");
      return 2;
    } else {
      lssh = (luassh_userdata_t *) lua_newuserdata(L, sizeof(*lssh));

      resSave = res;
      while(res) {
        lssh->socket = socket(
          res->ai_family,
          res->ai_socktype,
          res->ai_protocol);

        if(lssh->socket) {
          if(connect(lssh->socket, res->ai_addr, res->ai_addrlen) == 0)
            break;

          close(lssh->socket);
          lssh->socket = -1;
        }

        res = res->ai_next;
      }
      freeaddrinfo(resSave);

      if(lssh->socket == -1) {
        libssh2_exit();
        lua_pushnil(L);
        lua_pushstring(L, "failed to connect");
        return 2;
      } else {
        lssh->session = libssh2_session_init();
        if(!lssh->session ||
            (lssh->session && libssh2_session_handshake(lssh->session, lssh->socket))) {
          close(lssh->socket);
          libssh2_exit();
          lua_pushnil(L);
          lua_pushstring(L, "cannot initialize ssh session");
          return 2;
        }
      }
    }
  }

  lssh->fingerprint = libssh2_hostkey_hash(lssh->session, LIBSSH2_HOSTKEY_HASH_SHA1);
  luaL_getmetatable(L, "sshmeta");
  lua_setmetatable(L, -2);
  return 1;
}

static int sshmeta_close(lua_State *L) {
  luassh_userdata_t *lssh;
  lssh = (luassh_userdata_t *) luaL_checkudata(L, 1, "sshmeta");

  if(!lssh->socket) {
    libssh2_session_disconnect(lssh->session, "normal shutdown");
    libssh2_session_free(lssh->session);
    close(lssh->socket);
    libssh2_exit();
  }
  return 0;
}

static int sshmeta_hostKeyHash(lua_State *L) {
  luassh_userdata_t *lssh;
  unsigned char fingerprint[60];

  lssh = (luassh_userdata_t *) luaL_checkudata(L, 1, "sshmeta");
  _formatFingerprint(fingerprint, (unsigned char *) lssh->fingerprint, 20);
  lua_pushstring(L, fingerprint);
  return 1;
}

static int sshmeta_scpSend(lua_State *L) {
  luassh_userdata_t *lssh;
  char *src, *dest;
  struct stat finfo;
  lssh = (luassh_userdata_t *) luaL_checkudata(L, 1, "sshmeta");
  src = (char *) luaL_checkstring(L, 2);
  dest = (char *) luaL_checkstring(L, 3);

  if(stat(src, &finfo) < 0) {
    lua_pushnil(L);
    lua_pushstring(L, "no such file");
    return 2;
  } else {
    return _sendFile(L, lssh->session, src, dest, finfo);
  }
}

static int sshmeta_userAuthPassword(lua_State *L) {
  luassh_userdata_t *lssh;
  char *username, *password;
  lssh = (luassh_userdata_t *) luaL_checkudata(L, 1, "sshmeta");
  username = (char *) luaL_checkstring(L, 2);
  password = (char *) luaL_checkstring(L, 3);

  if(libssh2_userauth_password(lssh->session, username, password)) {
    lua_pushnil(L);
    lua_pushstring(L, "authentication error");
    return 2;
  }
}

static const struct luaL_Reg sshmeta_methods[] = {
  { "__gc", sshmeta_close },
  { "hostKeyHash", sshmeta_hostKeyHash },
  { "scpSend", sshmeta_scpSend },
  { "userAuthPassword", sshmeta_userAuthPassword },
  { NULL, NULL }
};

static const struct luaL_Reg luassh[] = {
  { "open", luassh_open },
  { NULL, NULL }
};

int luaopen_ssh(lua_State *L) {
  luaL_newmetatable(L, "sshmeta");
  lua_pushvalue(L, -1);
  lua_setfield(L, -2, "__index");
  luaL_setfuncs(L, sshmeta_methods, 0);

  luaL_newlib(L, luassh);
  return 1;
}
