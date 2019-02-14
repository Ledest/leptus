%% Copyright (c) 2013-2015 Sina Samavati <sina.samv@gmail.com>
%%
%% Permission is hereby granted, free of charge, to any person obtaining a copy
%% of this software and associated documentation files (the "Software"), to deal
%% in the Software without restriction, including without limitation the rights
%% to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
%% copies of the Software, and to permit persons to whom the Software is
%% furnished to do so, subject to the following conditions:
%%
%% The above copyright notice and this permission notice shall be included in
%% all copies or substantial portions of the Software.
%%
%% THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
%% IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
%% FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
%% AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
%% LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
%% OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
%% THE SOFTWARE.

%% a bunch of functions to deal with a request
-module(leptus_req).
-behaviour(gen_server).

%% -----------------------------------------------------------------------------
%% API
%% -----------------------------------------------------------------------------
-export([start_link/1, start/1, stop/1]).
-export([param/2,
         params/1,
         qs/1,
         qs_val/2,
         qs_vals/1,
         uri/1,
         version/1,
         method/1,
         body/1,
         body_raw/1,
         body_qs/1,
         header/2, header/3,
         parse_header/2,
         auth/2,
         peer/1,
         reply/4,
         get_req/1,
         set_req/2]).

%% -----------------------------------------------------------------------------
%% gen_server callbacks
%% -----------------------------------------------------------------------------
-export([init/1,
         handle_call/3,
         handle_cast/2,
         handle_info/2,
         terminate/2,
         code_change/3]).

%% -----------------------------------------------------------------------------
%% API
%% -----------------------------------------------------------------------------
-spec start_link(cowboy_req:req()) -> {ok, pid()} | ignore | {error, any()}.
start_link(Req) -> gen_server:start_link(?MODULE, Req, []).

-spec start(cowboy_req:req()) -> {ok, pid()} | ignore | {error, any()}.
start(Req) -> gen_server:start(?MODULE, Req, []).

-spec stop(pid()) -> ok.
stop(Pid) -> gen_server:call(Pid, stop).

-spec param(pid(), atom()) -> binary() | undefined.
param(Pid, Key) -> gen_server:call(Pid, {binding, Key}).

-spec params(pid()) -> [{atom(), binary()}] | undefined.
params(Pid) -> gen_server:call(Pid, bindings).

-spec qs(pid()) -> binary().
qs(Pid) -> gen_server:call(Pid, qs).

-spec qs_val(pid(), binary()) -> binary() | undefined.
qs_val(Pid, Key) ->
    case lists:keyfind(Key, 1, qs_vals(Pid)) of
        {_, V} -> V;
        false -> undefined
    end.

-spec qs_vals(pid()) -> [{binary(), binary() | true}].
qs_vals(Pid) -> cow_qs:parse_qs(qs(Pid)).

-spec uri(pid()) -> binary().
uri(Pid) ->
    %% e.g <<"/path?query=string">>
    case qs(Pid) of
        <<>> -> gen_server:call(Pid, path);
        QS -> <<(gen_server:call(Pid, path))/binary, "?", QS/binary>>
    end.

-spec version(pid()) -> cowboy:http_version().
version(Pid) -> gen_server:call(Pid, version).

-spec method(pid()) -> binary().
method(Pid) -> gen_server:call(Pid, method).

-spec body(pid()) -> binary() | [{binary(), binary() | true}] | jsx:json_term() | term().
body(Pid) ->
    case parse_header(Pid, <<"content-type">>) of
        {<<"application">>, Type, _} -> body_decode(Type, body_raw(Pid));
        _ -> body_raw(Pid)
    end.

-spec body_raw(pid()) -> binary() | {error, term()} | {more, binary()}.
body_raw(Pid) -> gen_server:call(Pid, body).

-spec body_qs(pid()) -> [{binary(), binary() | true}] | {error, term()}.
body_qs(Pid) ->
    case body_raw(Pid) of
        B when is_binary(B) -> cow_qs:parse_qs(B);
        {more, _} -> {error, badlength};
        B -> B
    end.

-spec header(pid(), binary()) -> binary() | undefined.
header(Pid, Name) -> gen_server:call(Pid, {header, Name}).

-spec header(pid(), binary(), Default) -> binary() | Default when Default :: any().
header(Pid, Name, Default) -> gen_server:call(Pid, {header, Name, Default}).

-spec parse_header(pid(), binary()) -> any() | undefined | {error, any()}.
parse_header(Pid, Name) -> gen_server:call(Pid, {parse_header, Name}).

-spec auth(pid(), basic) -> {binary(), binary()} | undefined | {error, any()}.
auth(Pid, basic) ->
    case parse_header(Pid, <<"authorization">>) of
        {<<"basic">>, UserPass} -> UserPass;
        UserPass -> UserPass
    end.

-spec peer(pid()) -> {inet:ip_address(), inet:port_number()}.
peer(Pid) -> gen_server:call(Pid, peer).

-spec reply(pid(), cowboy:http_status(), cowboy:http_headers(), iodata()) -> ok.
reply(Pid, Status, Headers, Body) -> gen_server:call(Pid, {reply, Status, Headers, Body}).

-spec get_req(pid()) -> cowboy_req:req().
get_req(Pid) -> gen_server:call(Pid, get_req).

-spec set_req(pid(), cowboy_req:req()) -> ok.
set_req(Pid, Req) -> gen_server:cast(Pid, {set_req, Req}).

%% -----------------------------------------------------------------------------
%% gen_server callbacks
%% -----------------------------------------------------------------------------
init(Req) -> {ok, Req}.

handle_call(stop, _From, Req) -> {stop, shutdown, ok, Req};
handle_call(get_req, _From, Req) -> {reply, Req, Req};
handle_call(body, _From, Req) ->
    case cowboy_req:body(Req) of
        {more, B, R} -> {reply, {more, B}, R};
        {ok, B, R} -> {reply, B, R};
        {error, _} = E -> {reply, E, Req}
    end;
handle_call({reply, Status, Headers, Body}, _From, Req) ->
    {ok, R} = cowboy_req:reply(Status, Headers, Body, Req),
    {reply, ok, R};
handle_call({header, Name, Default}, _From, Req) ->
    {V, R} = cowboy_req:header(Name, Req, Default),
    {reply, V, R};
handle_call({parse_header, Name}, _From, Req) ->
    case cowboy_req:parse_header(Name, Req) of
        {T, V, R} when T =:= ok; T =:= undefined -> {reply, V, R};
        {error, _} = E -> {reply, E, Req}
    end;
% binding, header
handle_call({F, A}, _From, Req) ->
    {V, R} = cowboy_req:F(A, Req),
    {reply, V, R};
% bindings, method, path, peer, qs, version
handle_call(F, _From, Req) when is_atom(F) ->
    {V, R} = cowboy_req:F(Req),
    {reply, V, R};
handle_call(_Msg, _From, Req) -> {noreply, Req}.

handle_cast({set_req, NewReq}, _Req) -> {noreply, NewReq};
handle_cast(_Msg, Req) -> {noreply, Req}.

handle_info(_Info, Req) -> {noreply, Req}.

terminate(_Reason, _Req) -> ok.

code_change(_OldVsn, Req, _Extra) -> {ok, Req}.

%% -----------------------------------------------------------------------------
%% internal
%% -----------------------------------------------------------------------------
-spec body_decode(Type::binary(), Body::binary()) -> binary().
body_decode(<<"x-www-form-urlencoded">>, Body) -> cow_qs:parse_qs(Body);
body_decode(<<"json">>, Body) ->
    try
        jsx:decode(Body)
    catch
        _:_ -> Body
    end;
body_decode(<<"msgpack">>, Body) ->
    case msgpack:unpack(Body) of
        {ok, UnpackedBody} -> UnpackedBody;
        _ -> Body
    end;
body_decode(Type, Body) when Type =:= <<"erlang">>; Type =:= <<"etf">> ->
    try
        binary_to_term(Body, [safe])
    catch
        _:_ -> Body
    end;
body_decode(_Type, Body) -> Body.
