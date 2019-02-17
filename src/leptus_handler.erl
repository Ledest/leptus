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

-module(leptus_handler).

%% -----------------------------------------------------------------------------
%% cowboy callbacks
%% -----------------------------------------------------------------------------
-export([init/3]).
-export([upgrade/4]).

-include("leptus.hrl").
-include("leptus_logger.hrl").

%% -----------------------------------------------------------------------------
%% types
%% -----------------------------------------------------------------------------
-type req() :: pid().
-type status() :: non_neg_integer() | binary() | atom().
-type headers() :: cowboy:http_headers().
-type body() :: binary() | string() | {json | msgpack, jsx:json_term()} | {erlang, term()} | {html, binary()}.
-type method() :: get | put | post | delete.
-type response() :: {body(), handler_state()} |
                    {status(), body(), handler_state()} |
                    {status(), headers(), body(), handler_state()}.
-type terminate_reason() :: normal | not_allowed | unauthenticated | no_permission | {error, any()}.
-type data_format() :: text | erlang | json | msgpack | html.
-type status_code() :: 100..101 | 200..206 | 300..307 | 400..417 | 500..505.

-export_type([status/0]).

%% -----------------------------------------------------------------------------
%% internal state record
%% -----------------------------------------------------------------------------
-record(state, {resrc = #resrc{} :: resrc(),
                method = <<"GET">> :: binary(),
                terminate_reason = normal :: terminate_reason(),
                log_data = #log_data{} :: log_data()}).
-type state() :: #state{}.

%% -----------------------------------------------------------------------------
%% cowboy callbacks
%% -----------------------------------------------------------------------------
init(_, Req, Resrc) ->
    {ok, ReqPid} = leptus_req_sup:start_child(Req),
    Method = leptus_req:method(ReqPid),
    {upgrade, protocol, ?MODULE, ReqPid,
     #state{resrc = Resrc, method = Method,
            log_data = #log_data{method = Method, headers = headers(Req)}}}.

upgrade(Req, Env, _Handler,
        #state{resrc = #resrc{handler = Handler, route = Route, handler_state = HState} = Resrc,
               log_data = LogData} = State) ->
    #state{terminate_reason = TerminateReason, resrc = #resrc{handler_state = HState2}} =
        try Handler:init(Route, Req, HState) of
            {ok, HState1} ->
                handle_request(http_method(State#state.method), Req,
                               State#state{resrc = Resrc#resrc{handler_state = HState1}});
            Else ->
                reply(500, Req),
                badmatch_error_info(Else, {Handler, init, 3}, Route, Req, State),
                State#state{terminate_reason = {error, badmatch}}
        catch Class:Reason ->
            Stacktrace = erlang:get_stacktrace(),
            reply(500, Req),
            error_info(Class, {Reason, Stacktrace}, Route, Req, HState),
            State#state{terminate_reason = {error, Reason}}
        end,
    LocalTime = erlang:localtime(),
    receive
        {Status, ContentLength} ->
            {IP, _} = leptus_req:peer(Req),
            LD = LogData#log_data{ip = IP, version = leptus_req:version(Req), uri = leptus_req:uri(Req),
                                  status = Status, content_length = ContentLength, response_time = LocalTime},
            lists:foreach(fun(T) -> spawn(leptus_logger, send_event, [T, LD]) end, [access_log, debug_log])
    after 10 -> ok
    end,
    handler_terminate(TerminateReason, Handler, Route, Req, HState2),
    {ok, leptus_req:stop(Req), Env}.

%% -----------------------------------------------------------------------------
%% internal
%% -----------------------------------------------------------------------------
-spec is_defined(module(), atom()) -> boolean().
is_defined(Handler, Func) -> erlang:function_exported(Handler, Func, 3).

-spec http_method(binary()) -> method() | options | not_allowed.
http_method(<<"GET">>) -> get;
http_method(<<"PUT">>) -> put;
http_method(<<"POST">>) -> post;
http_method(<<"DELETE">>) -> delete;
%% just to deal with CORS preflight request
http_method(<<"OPTIONS">>) -> options;
http_method(_) -> not_allowed.

%% -----------------------------------------------------------------------------
%% Handler:Method/3 (Method :: get | put | post | delete)
%% -----------------------------------------------------------------------------
-spec handle_request(not_allowed | options | method(), req(), state()) -> state().
handle_request(not_allowed, Req,
               #state{resrc = #resrc{handler_state = HandlerState, handler = Handler, route = Route}} = State) ->
    handle_response(method_not_allowed(Handler, Route, HandlerState), Req, State#state{terminate_reason = not_allowed});
handle_request(options, Req, #state{resrc = #resrc{handler_state = HandlerState}} = State) ->
    %% deal with CORS preflight request
    handle_options_request(Req, State, HandlerState, check_cors_preflight(Req, State));
handle_request(Func, Req, #state{resrc = #resrc{handler = Handler, route = Route, handler_state = HandlerState},
                                 method = Method} = State) ->
    %% reasponse and terminate reason
    case is_allowed(Handler, Func, Route, Method) of
        true -> case authorization(Handler, Route, Req, HandlerState) of
                    {true, HandlerState1} ->
                        try Handler:Func(Route, Req, HandlerState1) of
                            Response -> handle_response(Response, Req, State#state{terminate_reason = normal})
                        catch Class:Reason ->
                            error_info(Class, {Reason, erlang:get_stacktrace()}, Route, Req, HandlerState1),
                            handle_response({500, <<>>, HandlerState1}, Req,
                                            State#state{terminate_reason = {error, Reason}})
                        end;
                    {false, Response, TReason} -> handle_response(Response, Req, State#state{terminate_reason = TReason})
                end;
        false -> handle_response(method_not_allowed(Handler, Route, HandlerState), Req,
                                 State#state{terminate_reason = not_allowed})
    end.

check_cors_preflight(Req, #state{resrc = #resrc{handler = Handler, route = Route}}) ->
    Method = leptus_req:header(Req, <<"access-control-request-method">>),
    is_allowed(Handler, http_method(Method), Route, Method).

handle_options_request(Req, State, HandlerState, true) -> handle_response({<<>>, HandlerState}, Req, State);
handle_options_request(Req, State, _, false) -> handle_request(not_allowed, Req, State).

%% -----------------------------------------------------------------------------
%% Handler:is_authenticated/3 and Handler:has_permission/3
%% -----------------------------------------------------------------------------
-spec authorization(handler(), route(), req(), handler_state()) ->
          {true, handler_state()} | {false, response(), terminate_reason()}.
authorization(Handler, Route, Req, HandlerState) ->
    %%
    %% spec:
    %%   is_authenticated(Route, Req, State) ->
    %%     {true, State} | {false, Body, State} | {false, Headers, Body, State}.
    %%
    %%
    %% spec:
    %%   has_permission(Route, Req, State) ->
    %%     {true, State} | {false, Body, State} | {false, Headers, Body, State}.
    %%
    case case is_defined(Handler, is_authenticated) of
             true -> try Handler:is_authenticated(Route, Req, HandlerState) of
                         {true, _} = HandlerState1 -> HandlerState1;
                         {false, Body, HandlerState1} -> {false, {401, Body, HandlerState1}, unauthenticated};
                         {false, Headers, Body, HandlerState1} ->
                             {false, {401, Headers, Body, HandlerState1}, unauthenticated};
                         Else ->
                             badmatch_error_info(Else, {Handler, is_authenticated, 3}, Route, Req, HandlerState),
                             {false, {500, <<>>, HandlerState}, badmatch}
                     catch Class:Reason ->
                         error_info(Class, {Reason, erlang:get_stacktrace()}, Route, Req, HandlerState),
                         {false, {500, <<>>, HandlerState}, {error, Reason}}
                     end;
              false -> {true, HandlerState}
         end of
        {false, _, _} = Res -> Res;
        {true, HandlerState2} = Res ->
            case is_defined(Handler, has_permission) of
                true -> try Handler:has_permission(Route, Req, HandlerState2) of
                            {true, _} = HandlerState3 -> HandlerState3;
                            {false, Body1, HandlerState3} -> {false, {403, Body1, HandlerState3}, no_permission};
                            {false, Headers1, Body1, HandlerState3} ->
                                {false, {403, Headers1, Body1, HandlerState3}, no_permission};
                            Else1 ->
                                badmatch_error_info(Else1, {Handler, has_permission, 3}, Route, Req, HandlerState2),
                                {false, {500, <<>>, HandlerState2}, badmatch}
                        catch Class1:Reason1 ->
                            error_info(Class1, {Reason1, erlang:get_stacktrace()}, Route, Req, HandlerState2),
                            {false, {500, <<>>, HandlerState2}, {error, Reason1}}
                        end;
                false -> Res
            end
    end.

%% -----------------------------------------------------------------------------
%% Handler:allowed_methods/1
%% check if method allowed
%% -----------------------------------------------------------------------------
-spec is_allowed(handler(), method(), route(), binary()) -> boolean().
is_allowed(Handler, Func, Route, Method) ->
    %% check if Handler:Func/3 is exported
                                      %% check if the http method is existing in allowed methods list
                                      %% e.g.
                                      %%   lists:member(<<"GET">>, [<<"GET">>, <<"DELETE">>])
    is_defined(Handler, Func) andalso lists:member(Method, Handler:allowed_methods(Route)).

%% -----------------------------------------------------------------------------
%% Handler:allowed_methods/1
%% 'Method not Allowed' response
%% -----------------------------------------------------------------------------
-spec method_not_allowed(handler(), route(), handler_state()) -> response().
method_not_allowed(Handler, Route, HandlerState) ->
    %%
    %% spec:
    %%   allowed_methods(Route) -> [binary()]
    %% e.g.
    %%   allowed_methods("/") -> [<<"GET">>, <<"POST">>]
    %%
    {405, [{<<"allow">>, allowed_methods(Handler, Route)}], <<>>, HandlerState}.

-spec allowed_methods(handler(), route()) -> binary().
allowed_methods(Handler, Route) -> join_http_methods(Handler:allowed_methods(Route)).

%% -----------------------------------------------------------------------------
%% Handler:cross_domains/3
%% -----------------------------------------------------------------------------
-spec handler_cross_domains(handler(), route(), req(), handler_state()) -> {headers(), handler_state()}.
handler_cross_domains(Handler, Route, Req, HandlerState) ->
    %%
    %% spec:
    %%   Handler:cross_domains(Route, Req, State) -> {[string()], State}
    %%
    case leptus_req:header(Req, <<"origin">>) of
        undefined -> {[], HandlerState};
        Origin ->
            %% go on if the Origin header is present
            case is_defined(Handler, cross_domains) of
                false -> {[], HandlerState};
                true ->
                    %% go on if Handler:cross_domains/3 is exported
                    try Handler:cross_domains(Route, Req, HandlerState) of
                        {HostMatches, HandlerState1} ->
                            {case origin_matches(leptus_utils:get_uri_authority(Origin), HostMatches) of
                                 false -> [];
                                 %% go on if Origin is allowed
                                 true -> cors_headers(Handler, Route, Origin, Req)
                             end,
                             HandlerState1};
                        Else ->
                            badmatch_error_info(Else, {Handler, cross_domains, 3}, Route, Req, HandlerState),
                            throw(badmatch)
                    catch Class:Reason ->
                        error_info(Class, {Reason, erlang:get_stacktrace()}, Route, Req, HandlerState),
                        throw(Reason)
                    end
            end
    end.

-spec is_preflight(req()) -> boolean().
is_preflight(Req) -> leptus_req:header(Req, <<"access-control-request-method">>) =/= undefined.

-spec cors_headers(handler(), route(), binary(), req()) -> headers().
cors_headers(Handler, Route, Origin, Req) ->
    case is_preflight(Req) of
        true -> [{<<"access-control-allow-origin">>, Origin},
                 {<<"access-control-allow-methods">>, allowed_methods(Handler, Route)}];
        false -> [{<<"access-control-allow-origin">>, Origin}]
    end.

%% -----------------------------------------------------------------------------
%% Handler:terminate/4
%% -----------------------------------------------------------------------------
-spec handler_terminate(terminate_reason(), handler(), route(), req(), handler_state()) -> ok.
handler_terminate(Reason, Handler, Route, Req, HandlerState) -> Handler:terminate(Reason, Route, Req, HandlerState).

%% -----------------------------------------------------------------------------
%% reply - prepare stauts, headers and body
%% -----------------------------------------------------------------------------
-spec handle_response(response(), req(), state()) -> state().
handle_response({Body, HandlerState}, Req, #state{resrc = Resrc} = State) ->
    handle_response(200, [], Body, Req, State#state{resrc = Resrc#resrc{handler_state = HandlerState}});
handle_response({Status, Body, HandlerState}, Req, #state{resrc = Resrc} = State) ->
    handle_response(Status, [], Body, Req, State#state{resrc = Resrc#resrc{handler_state = HandlerState}});
handle_response({Status, Headers, Body, HandlerState}, Req, #state{resrc = Resrc} = State) ->
    handle_response(Status, Headers, Body, Req, State#state{resrc = Resrc#resrc{handler_state = HandlerState}}).

-spec handle_response(status(), headers(), body(), req(), state()) -> state().
handle_response(Status, Headers, Body, Req, #state{terminate_reason = {error, _}} = State) ->
    reply(Status, Headers, Body, Req),
    State;
handle_response(Status, Headers, Body, Req, #state{resrc = #resrc{handler = Handler, route = Route,
                                                                  handler_state = HandlerState} = Resrc} = State) ->
    %% enable or disable cross-domain requests
    try handler_cross_domains(Handler, Route, Req, HandlerState) of
        {Headers2, HandlerState1} ->
            %% encode Body and set content-type
            {Headers1, Body1} = prepare_headers_body(Headers, Body),
            reply(status(Status), Headers1 ++ Headers2, Body1, Req),
            State#state{resrc = Resrc#resrc{handler_state = HandlerState1}}
    catch _:Reason ->
        reply(500, Req),
        State#state{terminate_reason = {error, Reason}}
    end.

-spec reply(status(), headers(), body(), req()) -> ok.
reply(Status, Headers, Body, Req) ->
    %% used in upgrade/4 for logging purposes
    self() ! {Status, iolist_size(Body)},
    leptus_req:reply(Req, Status, Headers, Body).

-spec reply(status(), req()) -> ok.
reply(Status, Req) ->
    %% used in upgrade/4 for logging purposes
    self() ! {Status, 0},
    leptus_req:reply(Req, Status).

-spec prepare_headers_body(headers(), body()) -> {headers(), body()}.
prepare_headers_body(Headers, {Type, Body}) when Type =:= erlang; Type =:= etf ->
    {maybe_set_content_type(Type, Headers), term_to_binary(Body)};
prepare_headers_body(Headers, {json, Body}) -> {maybe_set_content_type(json, Headers), jsx:encode(Body)};
prepare_headers_body(Headers, {msgpack, Body}) ->
    {maybe_set_content_type(msgpack, Headers), msgpack:pack(Body, [{map_format, jsx}])};
prepare_headers_body(Headers, {html, Body}) -> {maybe_set_content_type(html, Headers), Body};
prepare_headers_body(Headers, Body) -> {maybe_set_content_type(text, Headers), Body}.

-spec maybe_set_content_type(data_format(), headers()) -> headers().
maybe_set_content_type(Type, Headers) ->
    %% don't set content-type if it's already been set
    case lists:any(fun({N, _}) -> cowboy_bstr:to_lower(N) =:= <<"content-type">>;
                      (_) -> false
                   end, Headers) of
        true -> Headers;
        _false -> [{<<"content-type">>, content_type(Type)}|Headers]
    end.

-spec content_type(data_format()) -> binary().
content_type(text) -> <<"text/plain">>;
content_type(html) -> <<"text/html">>;
content_type(erlang) -> <<"application/erlang">>;
content_type(etf) -> <<"application/etf">>;
content_type(json) -> <<"application/json">>;
content_type(msgpack) -> <<"application/msgpack">>.

%% -----------------------------------------------------------------------------
%% HTTP status code bindings
%% -----------------------------------------------------------------------------
-spec status(atom() | A) -> status_code() | A when A :: any().
%% informational
status(continue) -> 100;
status(switching_protocols) -> 101;
%% successful
status(ok) -> 200;
status(created) -> 201;
status(accepted) -> 202;
status(non_authoritative_information) -> 203;
status(no_content) -> 204;
status(reset_content) -> 205;
status(partial_content) -> 206;
%% redirection
status(multiple_choices) -> 300;
status(moved_permanently) -> 301;
status(found) -> 302;
status(see_other) -> 303;
status(not_modified) -> 304;
status(use_proxy) -> 305;
status(switch_proxy) -> 306;
status(temporary_redirect) -> 307;
%% client error
status(bad_request) -> 400;
status(unauthorized) -> 401;
status(payment_required) -> 402;
status(forbidden) -> 403;
status(not_found) -> 404;
status(not_allowed) -> 405;
status(not_acceptable) -> 406;
status(proxy_authentication_required) -> 407;
status(request_timeout) -> 408;
status(conflict) -> 409;
status(gone) -> 410;
status(length_required) -> 411;
status(precondition_failed) -> 412;
status(request_entity_too_large) -> 413;
status(request_uri_too_long) -> 414;
status(unsupported_media_type) -> 415;
status(requested_range_not_satisfiable) -> 416;
status(expectation_failed) -> 417;
%% server error
status(internal_server_error) -> 500;
status(not_implemented) -> 501;
status(bad_gateway) -> 502;
status(service_unavailable) -> 503;
status(gateway_timeout) -> 504;
status(http_version_not_supported) -> 505;
status(A) -> A.

-spec join_http_methods([binary()]) -> binary().
join_http_methods(Methods) -> list_to_binary(leptus_utils:join(<<", ">>, Methods)).

-spec compile_host(string() | binary()) -> [[binary() | atom()]] | [atom()].
compile_host(HostMatch) -> [X || {X, _, _} <- cowboy_router:compile([{HostMatch, []}])].

-spec origin_matches(binary(), [atom() | string() | binary()]) -> boolean().
origin_matches(Origin, HostMatches) ->
    %% [<<"com">>, <<"example">>], "example.com", [...]
    domains_match(hd(compile_host(Origin)), HostMatches).

%% TODO: write tests
domains_match(_, []) -> false;
domains_match(OriginToks, [HostMatch|Rest]) ->
    %% [<<"com">>, <<"example">>], [[<<"com">>, <<"example">>], ...], [...]
    domains_match(OriginToks, compile_host(HostMatch), Rest, OriginToks).

domains_match(_, ['_'], _, _) -> true;
domains_match(OriginToks, [HMToks|Rest], HostMatches, OriginToks) ->
    domain_matches(OriginToks, HMToks, Rest, HostMatches, OriginToks).

domain_matches(OriginToks, OriginToks, _, _, _) -> true;
domain_matches(_, ['...'|_], _, _, _) -> true;
domain_matches([_|T], ['_'|HMToks], Rest, HostMatches, OriginToksReplica) ->
    domain_matches(T, HMToks, Rest, HostMatches, OriginToksReplica);
domain_matches([H|T], [H|HMToks], Rest, HostMatches, OriginToksReplica) ->
    domain_matches(T, HMToks, Rest, HostMatches, OriginToksReplica);
domain_matches(_, _, [HMToks|Rest], HostMatches, OriginToksReplica) ->
    domain_matches(OriginToksReplica, HMToks, Rest, HostMatches, OriginToksReplica);
domain_matches(_, _, [], [], _) -> false;
domain_matches(_, _, [], HostMatches, OriginToks) -> domains_match(OriginToks, HostMatches).

badmatch_error_info(Value, MFA, Route, Req, State) ->
    error_logger:error_msg("** Leptus handler terminating~n"
                           "** Bad return value in ~p~n"
                           "** Route == ~p~n"
                           "** Req == ~p~n"
                           "** Handler state == ~p~n"
                           "** Return value == ~p~n",
                           [MFA, Route, Req, State, Value]).

error_info(Class, Reason, Route, Req, State) ->
    error_logger:error_msg("** Leptus handler terminating~n"
                           "** Exception class ~p in process ~p~n"
                           "** Route == ~p~n"
                           "** Req == ~p~n"
                           "** Handler state == ~p~n"
                           "** Reason for termination ==~n"
                           "** ~p~n",
                           [Class, self(), Route, Req, State, Reason]).

headers(Req) ->
    {Headers, _} = cowboy_req:headers(Req),
    Headers.
-compile({inline, [headers/1]}).
