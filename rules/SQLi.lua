--[[
规则名称: SQl注入

过滤阶段: 请求阶段

危险等级: 严重

规则描述: 对sql注入防护进行补充，增加FIELD()、position()等函数构造布尔盲注和基于时间的盲注进行防护
--]]


local kvFilter = waf.kvFilter
local rgx = waf.rgxMatch

local function sMatch(v)
    local m = rgx(v, "\\((?:(?:#|--).*?\\n|/\\*.*?\\*/|\\s|\\xa0|\\()*select\\b", "joi")
    if m then
        return m, v
    end
    m = rgx(v, "union(?:(?:#|--).*?\\n|/\\*.*?\\*/|\\s|\\xa0|\\()+(?:select\\b|all\\b|distinct)", "joi")
    if m then
        return m, v
    end
    m = rgx(v, "(?i:\\b(?:c(?:o(?:n(?:v(?:ert(?:_tz)?)?|cat(?:_ws)?|nection_id)|(?:mpres)?s|ercibility|(?:un)?t|alesce)|ur(?:rent_(?:time(?:stamp)?|date|user)|(?:dat|tim)e)|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|ast|r32)|s(?:t(?:d(?:dev(?:_(?:sam|po)p)?)?|r(?:_to_date|cmp))|u(?:b(?:str(?:ing(?:_index)?)?|(?:dat|tim)e)|m)|e(?:c(?:_to_time|ond)|ssion_user)|ys(?:tem_user|date)|ha[12]?|oundex|chema|ig?n|leep|pace|qrt)|i(?:s(?:_(?:ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|(?:free|used)_lock)|null)?|n(?:et(?:6_(?:aton|ntoa)|_(?:aton|ntoa))|s(?:ert|tr)|terval)?|f(?:null)?)|d(?:a(?:t(?:e(?:_(?:format|add|sub)|diff)?|abase)|y(?:of(?:month|week|year)|name)?)|e(?:(?:s_(?:de|en)cryp|faul)t|grees|code)|count|ump)|l(?:o(?:ca(?:l(?:timestamp)?|te)|g(?:10|2)?|ad_file|wer)|ast(?:_(?:insert_id|day))?|e(?:(?:as|f)t|ngth)|case|trim|pad|n)|u(?:n(?:compress(?:ed_length)?|ix_timestamp|hex)|tc_(?:time(?:stamp)?|date)|p(?:datexml|per)|uid(?:_short)?|case|ser)|r(?:a(?:wto(?:nhex(?:toraw)?|hex)|dians|nd)|e(?:p(?:lace|eat)|lease_lock|verse)|o(?:w_count|und)|ight|trim|pad)|t(?:ime(?:_(?:format|to_sec)|stamp(?:diff|add)?|diff)?|o_(?:(?:second|day)s|base64|n?char)|r(?:uncate|im)|an)|m(?:a(?:ke(?:_set|date)|ster_pos_wait|x)|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:nth(?:name)?|d)|d5)|f(?:i(?:eld(?:_in_set)?|nd_in_set)|rom_(?:unixtime|base64|days)|o(?:und_rows|rmat)|loor)|p(?:o(?:w(?:er)?|sition)|eriod_(?:diff|add)|rocedure_analyse|assword|g_sleep|i)|a(?:s(?:cii(?:str)?|in)|es_(?:de|en)crypt|dd(?:dat|tim)e|(?:co|b)s|tan2?|vg)|b(?:i(?:t_(?:length|count|x?or|and)|n(?:_to_num)?)|enchmark)|e(?:x(?:tract(?:value)?|p(?:ort_set)?)|nc(?:rypt|ode)|lt)|g(?:r(?:oup_conca|eates)t|et_(?:format|lock))|v(?:a(?:r(?:_(?:sam|po)p|iance)|lues)|ersion)|o(?:(?:ld_passwo)?rd|ct(?:et_length)?)|we(?:ek(?:ofyear|day)?|ight_string)|n(?:o(?:t_in|w)|ame_const|ullif)|h(?:ex(?:toraw)?|our)|qu(?:arter|ote)|year(?:week)?|xmltype)\\W*?\\()", "jos")
    if m then
        return m, v
    end
    m = rgx(v, "(?i:(?:;\\s*?shutdown\\s*?(?:[#;]|\\/\\*|--|\\{)|waitfor\\s*?delay\\s?[\\\"'`]+\\s?\\d|select\\s*?sleep))", "jos")
    if m then
        return m, v
    end
    return false
end

local form = waf.form
if form then
    local m, d = kvFilter(form["FORM"], sMatch)
    if m then
        return m, d, true
    end
end

local queryString = waf.queryString
if queryString then
    local m, d = kvFilter(queryString, sMatch)
    if m then
        return m, d, true
    end
end

local cookies = waf.cookies
if cookies then
    local m, d = kvFilter(cookies, sMatch)
    if m then
        return m, d, true
    end
end

local m, d = kvFilter(waf.reqHeaders, sMatch)
if m then
    return m, d, true
end
return false
