local ffi = require("ffi")

ffi.cdef[[
int printf(const char *fmt, ...);
int myfce(int a, int b);
]]

function Split(s)
    result = {};
    for match in string.gmatch(s, "%S+") do
        table.insert(result, match);
    end
    return result;
end

ffi.load("mylib", true)

--ffi.C.printf("Hello world from %s!", "Lua")

local args = ngx.req.get_uri_args()

for key, val in pairs(args) do
  --ngx.say(key, ": ", val)
  params =  Split(key, " ")
end

--ngx.print("a=",params[1], "b=", params[2])
a=tonumber(params[1])
b=tonumber(params[2])

soucet = ffi.C.myfce(a,b)

ngx.say("<div align=center><h2>", a, " + ", b, " = ", soucet, "</h2></div>")

local h, err = ngx.resp.get_headers()

ngx.say("<h3>Request headers</h3>");
for k, v in pairs(h) do
   ngx.say(k, ": ", v, "<br>");
end

