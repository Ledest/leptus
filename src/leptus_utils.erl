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

-module(leptus_utils).

%% -----------------------------------------------------------------------------
%% API
%% -----------------------------------------------------------------------------
-export([priv_dir/1]).
-export([paginator/1]).
-export([paginate/3]).
-export([listener_bucket/1]).
-export([listener_handlers/1]).
-export([print_listener_info/1]).
-export([get_uri_authority/1]).

-include("leptus_stats.hrl").

%% -----------------------------------------------------------------------------
%% find the path to the priv directory in an application
%% -----------------------------------------------------------------------------
-spec priv_dir(atom()) -> file:name_all() | {error, bad_name}.
priv_dir(App) ->
    case code:priv_dir(App) of
        {error, bad_name} = E -> case code:which(App) of
                                     non_existing -> E;
                                     BeamFile -> filename:join(filename:dirname(filename:dirname(BeamFile)), "priv")
                                 end;
        PrivDir -> PrivDir
    end.

%% -----------------------------------------------------------------------------
%% generate a paginator
%% -----------------------------------------------------------------------------
-spec paginator(non_neg_integer()) -> fun((non_neg_integer(), list()) -> list()).
paginator(NElemPerPage) -> fun(Page, Objects) -> paginate(NElemPerPage, Objects, Page) end.

%% -----------------------------------------------------------------------------
%% paginate a list of objects
%% -----------------------------------------------------------------------------
-spec paginate(non_neg_integer(), list(), non_neg_integer()) -> list().
paginate(NElemPerPage, Objects, Page) ->
    Last = Page * NElemPerPage,
    Start = Last - NElemPerPage,
    lists:sublist(Objects, Start + 1, Last - Start).

%% -----------------------------------------------------------------------------
%% get a listener bucket
%% -----------------------------------------------------------------------------
listener_bucket(Listener) -> get_value(Listener, leptus_config:lookup(listeners, []), not_found).

%% -----------------------------------------------------------------------------
%% get handlers of a running listener
%% -----------------------------------------------------------------------------
listener_handlers(Listener) ->
    case listener_bucket(Listener) of
        #listener_bucket{handlers = Handlers} -> Handlers;
        not_found -> {error, not_found}
    end.

%% -----------------------------------------------------------------------------
%% print a running listener information
%% -----------------------------------------------------------------------------
print_listener_info(Listener) ->
    io:fwrite("~-30s ~-44s ~15s~n"
              "~.98c~n~n",
              ["Handler", "Route", "Allowed methods",
               $=]),
    lists:foreach(fun({M, _}) ->
                      Prefix = try
                                   M:prefix()
                               catch _:_ -> ""
                               end,
                      lists:foreach(fun(R) -> print(M, Prefix, R) end, M:routes());
                     (_) -> ok
                  end, lists:foldl(fun({_, A}, Acc) -> Acc ++ A end, [], listener_handlers(Listener))).

get_uri_authority(URI) -> get_uri_authority(URI, <<>>).

%% -----------------------------------------------------------------------------
%% internal
%% -----------------------------------------------------------------------------
print(Handler, Prefix, Route) ->
    io:fwrite("~-30s ~-44s ~-22s~n", [Handler, Prefix ++ Route, allowed_methods(Handler, Route)]).

allowed_methods(Handler, Route) -> list_to_binary(lists:join(<<", ">>, Handler:allowed_methods(Route))).

get_value(Key, Opts, Default) ->
    case lists:keyfind(Key, 1, Opts) of
        {_, Value} -> Value;
        _ -> Default
    end.

get_uri_authority(<<>>, Acc) -> Acc;
get_uri_authority(<<$/, _/binary>>, Acc) ->
    %% skip the rest
    Acc;
get_uri_authority(<<"://", Rest/binary>>, _) ->
    %% skip scheme
    get_uri_authority(Rest, <<>>);
get_uri_authority(<<Char:1/binary, Rest/binary>>, Acc) -> get_uri_authority(Rest, <<Acc/binary, Char/binary>>).
