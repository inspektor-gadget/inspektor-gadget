acc = nil
wr = nil
ds = nil
events = 0

function init(ctx)
    ctx:Log("Hello from Lua")
    ds = ctx:GetDataSource("exec")
    nds = ctx:AddDataSource("foo")
    ndsField = nds:AddField("hooray")
    -- ds:demo("yay")
    acc = ds:GetField("args")
    wr = ds:AddField("luaval")

    newTicker(1000, "tick")
end

function preStart(ctx)
    ds:Subscribe("yeah")
end

function start(ctx)
end

function stop(ctx)
    local ndata = nds:NewData()
    ndsField:SetString(ndata, ""..events.." events")
    nds:EmitAndRelease(ndata)

    ctx:Log("bye from lua")
end

function tick()
    local ndata = nds:NewData()
    ndsField:SetString(ndata, "ticker event")
    nds:EmitAndRelease(ndata)
end

function yeah(ds, data)
    local str = acc:GetString(data)
    wr:SetString(data, "lua:"..str)

    events = events + 1

    local ndata = nds:NewData()
    ndsField:SetString(ndata, "dabba")
    nds:EmitAndRelease(ndata)
end