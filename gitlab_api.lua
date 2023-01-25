local ffi   = require("ffi")
local curl  = require'libcurl'
local cjson = require("cjson.safe")

local function checkingParameters(username, token)
    if username ~= nil and username ~= "" then
        if token ~= nil and username ~= "" then
            return true
        else
            return false, "Checking parameters: No token"
        end
    else
       return false, "Checking parameters: No username"
    end
end

local function sendRequest(type, url, token, http_response, handleDelegate)
    http_response.error = ""
    local easy = curl.easy{
        ssl_verifyhost = false,
        ssl_verifypeer = false,
        url = url,
        customrequest = type,
        writefunction = handleDelegate
    }
    if token then
        easy:set("httpheader", {token})
    end
    easy:perform()
    http_response.http_code = easy:info("response_code") or ""
    easy:close()
end

local function processingResponseUserInformation(raw, http_response)
    local data = ffi.string(ffi.cast("char*", raw))
    local _, endPosition = string.find(data, "id\":", 1)
    if endPosition then
        local startPosition, _ = string.find(data, ",", endPosition)
        http_response.user_id = string.sub(data, endPosition+1, startPosition-1)
    else
        http_response.error = data
    end
    return #data
end

local function processingResponseUserTokenInformation(raw, user_id, http_response)
    local data = ffi.string(ffi.cast("char*", raw))
    local _, _endPos = string.find(data,  "}]", 1)
    data = data:sub(1,_endPos)
    local _, endPosition = string.find(data,  "\"user_id\":" .. user_id, 1)
    if endPosition then
        http_response.list_id_tokens = {}
        for i, val in ipairs(cjson.decode(data)) do
            http_response.list_id_tokens[i]= val.id
        end
    else
        http_response.error = data
    end
    return #data
end

local function processingResponseDeleteToken(raw, http_response)
    local data = ffi.string(ffi.cast("char*", raw))
    if data ~= "" then
        http_response.error = data
    end
    return #data
end

local function RequestGettingUserInformation(username, url_gitlab)
    local http_response = {}
    sendRequest("GET", url_gitlab .. "users/?username=" .. username, nil, http_response,
        function(raw)
            return processingResponseUserInformation(raw, http_response)
        end)
    if http_response.error ~= "" or http_response.http_code == 0 then
        local errorBuffer
        if  http_response.http_code == 404 and string.find(http_response.error, "API Version Not Found", 1) then --ошибка неверного адреса до сервера gitlabAPI
            errorBuffer  = "404 API Version Not Found. Check configuration gitlabAPI URL:" .. url_gitlab
        elseif http_response.http_code == 200 and http_response.error == "[]" then --ошибка user_name
            errorBuffer = "User_name not found."
        elseif http_response.http_code == 0 then --ошибка недоступности до ГитЛаба
            errorBuffer = "The server is not available."
        else
            errorBuffer = http_response.http_code .. " " .. http_response.error
        end
        return false, errorBuffer
    end
    return true, http_response.user_id
end

local function RequestGettingUserTokensInformation(user_id, token, url_gitlab)
    local http_response = {}
    sendRequest("GET", url_gitlab .. "personal_access_tokens/?user_id=" .. user_id, token, http_response,
        function(raw)
            return processingResponseUserTokenInformation(raw, user_id, http_response)
        end)

    if http_response.error ~= "" or http_response.http_code == 0 then
        local errorBuffer
        if  http_response.http_code == 404 and string.find(http_response.error, "API Version Not Found", 1) then --ошибка неверного адреса до сервера gitlabAPI
            errorBuffer  = "404 API Version Not Found. Check configuration gitlabAPI URL:" .. url_gitlab
        elseif http_response.http_code == 401 and string.find(http_response.error, "401 Unauthorized", 1) then --ошибка user_id или токена
            errorBuffer = http_response.http_code .. ". Error in user_id or private_token."
        elseif http_response.http_code == 401 and string.find(http_response.error, "Token was revoked", 1) then --ошибка. Неверный токен. Этот токен был отозван.
            errorBuffer = "401 Unauthorized. Invalid token. Token was revoked. You have to re-authorize from the user."
        elseif http_response.http_code == 400 and string.find(http_response.error, "user_id is invalid", 1) then --ошибка. Неверный токен. Этот токен был отозван.
            errorBuffer = "401 Bad Request. user_id is invalid."
        elseif http_response.http_code == 0 then --ошибка недоступности до ГитЛаба
            errorBuffer = "The server is not available."
        else
            errorBuffer = http_response.http_code .. " " .. http_response.error
        end
        return false, errorBuffer
    end
    return true, http_response.list_id_tokens
end

local function RequestDeleteUserToken(token, delete_token, url_gitlab)
    local http_response = {}
    sendRequest("DELETE", url_gitlab .. "personal_access_tokens/" .. delete_token, token, http_response,
        function(raw)
            return processingResponseDeleteToken(raw, http_response)
        end)

    if http_response.error ~= "" or http_response.http_code == 0 then
        local errorBuffer
        if  http_response.http_code == 404 and string.find(http_response.error, "API Version Not Found", 1) then --ошибка неверного адреса до сервера gitlabAPI
            errorBuffer  = "404 API Version Not Found. Check configuration gitlabAPI URL:" .. url_gitlab
        elseif http_response.http_code == 404 then --ошибка user_id
            errorBuffer = "404 Not found. User_id not found. Or "
        elseif http_response.http_code == 401 and string.find(http_response.error, "401 Unauthorized", 1) then --ошибка. Неверный токен. Этот токен не отозван. Вероятно, токен не того юзера
            errorBuffer = "401 Unauthorized. Invalid token. It's probably another user's token."
        elseif http_response.http_code == 401 and string.find(http_response.error, "Token was revoked", 1) then --ошибка. Неверный токен. Этот токен был отозван.
            errorBuffer = "401 Unauthorized. Invalid token. Token was revoked. You have to re-authorize from the user."
        elseif http_response.http_code == 0 then --ошибка недоступности до ГитЛаба
            errorBuffer = "The server is not available."
        else
            errorBuffer = http_response.http_code .. " " .. http_response.error
        end
        return false, errorBuffer
    end
    return true
end

local function retryOperation(attempt_count, func, ...)
    local success, buffer
    for i = 1, attempt_count do
        success, buffer = func(...)
        if success then
            return success, buffer --если успешно выполнился запрос, то выходим с результатом
        elseif success == false and buffer ~= "The server is not available." then
            return false, buffer --если неуспешно выполнился запрос и если ошибка НЕ "не доступен сервер",
            -- а например "неверный токен", то выходим с результатом ошибки
        end
        --если ошибка "недоступен сервер", то продолжаем цикл
        __api.await(i*100)
    end
    return false, buffer
end

local function checkTrustedUsers (username, list_trusted_users)
    if list_trusted_users then
        for _, trusted_username in ipairs(list_trusted_users) do
            if username == trusted_username then
                return false, "This user is trusted."
            end
        end
    end
    return true
end

local function DeleteUserTokens(username, token, url_gitlab, list_trusted_users)
    local success, buffer = checkTrustedUsers(username, list_trusted_users)
    if not success then
        return false, buffer
    end

    local attempt_count = 3
    success, buffer = retryOperation(attempt_count, RequestGettingUserInformation, username, url_gitlab)
    if not success then
        return false, buffer
    end


    success, buffer = retryOperation(attempt_count, RequestGettingUserTokensInformation, buffer, token, url_gitlab)
    if not success then
        return false, buffer
    end

    for _, delete_token in ipairs(buffer) do
        success, buffer = retryOperation(attempt_count, RequestDeleteUserToken, token, 2875, url_gitlab)
        if not success then
            return false, buffer
        end
    end
    return true
end
return {
    DeleteUserTokens = DeleteUserTokens,
    checkingParameters = checkingParameters
}