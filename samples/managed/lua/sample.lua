-- RevLens Lua bytecode fixture
local greeting = "hello"
local count = 42
local ratio = 2.5

local function add(a, b)
  return a + b
end

function shout(name, ...)
  local parts = { greeting, name, ... }
  return string.upper(table.concat(parts, " "))
end

local t = {}
for i = 1, count do
  t[#t + 1] = add(i, ratio)
end
return shout("revlens"), #t
