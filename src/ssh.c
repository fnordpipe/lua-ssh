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
} luassh_userdata_t;

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

static const struct luaL_Reg sshmeta_methods[] = {
  { "__gc", sshmeta_close },
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