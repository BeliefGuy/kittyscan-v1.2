package lib

import (
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/checker/decls"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/interpreter/functions"
	"github.com/shadow1ng/fscan/common"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
	"io"
	"math/rand"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

func NewEnv(c *CustomLib) (*cel.Env, error) {
	return cel.NewEnv(cel.Lib(c))
}

func Evaluate(env *cel.Env, expression string, params map[string]interface{}) (ref.Val, error) {
	if expression == "" {
		return types.Bool(true), nil
	}
	// N1: response 在 cel 环境里声明为 object type(lib.Response, 见 NewEnvOption),
	// 而该 proto 类型(http.pb.go, 不在可改文件内)没有 raw_header 字段, 直接编译会报
	// "undeclared reference to 'raw_header'" 导致引用它的 8 个 POC 永远 false。
	// 这里在编译前把字段访问改写成 raw_header(response) 函数调用(声明/实现见 NewEnvOption
	// 与 BuildRawHeader), 其余表达式原样编译, 既有规则的类型检查行为不受影响。
	if strings.Contains(expression, "response.raw_header") {
		expression = strings.ReplaceAll(expression, "response.raw_header", "raw_header(response)")
	}
	ast, iss := env.Compile(expression)
	if iss.Err() != nil {
		//fmt.Printf("compile: ", iss.Err())
		return nil, iss.Err()
	}

	prg, err := env.Program(ast)
	if err != nil {
		//fmt.Printf("Program creation error: %v", err)
		return nil, err
	}

	out, _, err := prg.Eval(params)
	if err != nil {
		//fmt.Printf("Evaluation error: %v", err)
		return nil, err
	}
	return out, nil
}

func UrlTypeToString(u *UrlType) string {
	var buf strings.Builder
	if u.Scheme != "" {
		buf.WriteString(u.Scheme)
		buf.WriteByte(':')
	}
	if u.Scheme != "" || u.Host != "" {
		if u.Host != "" || u.Path != "" {
			buf.WriteString("//")
		}
		if h := u.Host; h != "" {
			buf.WriteString(u.Host)
		}
	}
	path := u.Path
	if path != "" && path[0] != '/' && u.Host != "" {
		buf.WriteByte('/')
	}
	if buf.Len() == 0 {
		if i := strings.IndexByte(path, ':'); i > -1 && strings.IndexByte(path[:i], '/') == -1 {
			buf.WriteString("./")
		}
	}
	buf.WriteString(path)

	if u.Query != "" {
		buf.WriteByte('?')
		buf.WriteString(u.Query)
	}
	if u.Fragment != "" {
		buf.WriteByte('#')
		buf.WriteString(u.Fragment)
	}
	return buf.String()
}

type CustomLib struct {
	envOptions     []cel.EnvOption
	programOptions []cel.ProgramOption
}

func NewEnvOption() CustomLib {
	c := CustomLib{}

	c.envOptions = []cel.EnvOption{
		cel.Container("lib"),
		cel.Types(
			&UrlType{},
			&Request{},
			&Response{},
			&Reverse{},
		),
		cel.Declarations(
			decls.NewIdent("request", decls.NewObjectType("lib.Request"), nil),
			decls.NewIdent("response", decls.NewObjectType("lib.Response"), nil),
			decls.NewIdent("reverse", decls.NewObjectType("lib.Reverse"), nil),
		),
		cel.Declarations(
			// functions
			decls.NewFunction("bcontains",
				decls.NewInstanceOverload("bytes_bcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("bmatches",
				decls.NewInstanceOverload("string_bmatches_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("md5",
				decls.NewOverload("md5_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("randomInt",
				decls.NewOverload("randomInt_int_int",
					[]*exprpb.Type{decls.Int, decls.Int},
					decls.Int)),
			decls.NewFunction("randomLowercase",
				decls.NewOverload("randomLowercase_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("randomUppercase",
				decls.NewOverload("randomUppercase_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("randomString",
				decls.NewOverload("randomString_int",
					[]*exprpb.Type{decls.Int},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64",
				decls.NewOverload("base64_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("base64Decode",
				decls.NewOverload("base64Decode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urlencode",
				decls.NewOverload("urlencode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_string",
					[]*exprpb.Type{decls.String},
					decls.String)),
			decls.NewFunction("urldecode",
				decls.NewOverload("urldecode_bytes",
					[]*exprpb.Type{decls.Bytes},
					decls.String)),
			decls.NewFunction("substr",
				decls.NewOverload("substr_string_int_int",
					[]*exprpb.Type{decls.String, decls.Int, decls.Int},
					decls.String)),
			decls.NewFunction("wait",
				decls.NewInstanceOverload("reverse_wait_int",
					[]*exprpb.Type{decls.Any, decls.Int},
					decls.Bool)),
			decls.NewFunction("icontains",
				decls.NewInstanceOverload("icontains_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("TDdate",
				decls.NewOverload("tongda_date",
					[]*exprpb.Type{},
					decls.String)),
			decls.NewFunction("shirokey",
				decls.NewOverload("shiro_key",
					[]*exprpb.Type{decls.String, decls.String},
					decls.String)),
			decls.NewFunction("startsWith",
				decls.NewInstanceOverload("startsWith_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			decls.NewFunction("istartsWith",
				decls.NewInstanceOverload("startsWith_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.Bool)),
			decls.NewFunction("hexdecode",
				decls.NewInstanceOverload("hexdecode",
					[]*exprpb.Type{decls.String},
					decls.Bytes)),
			// N1: ibcontains —— bytes 不区分大小写包含, 用友NC等 POC 的
			// response.raw_header.ibcontains(b"X-T0KEN") / response.body.ibcontains(...) 依赖它。
			decls.NewFunction("ibcontains",
				decls.NewInstanceOverload("bytes_ibcontains_bytes",
					[]*exprpb.Type{decls.Bytes, decls.Bytes},
					decls.Bool)),
			// N1/N2: bsubmatch —— xray 的 '"regex".bsubmatch(target)' 提取命名捕获组,
			// 返回 map<string,string>, output 段用 search["name"] 取值。
			decls.NewFunction("bsubmatch",
				decls.NewInstanceOverload("string_bsubmatch_bytes",
					[]*exprpb.Type{decls.String, decls.Bytes},
					decls.NewMapType(decls.String, decls.String)),
				decls.NewInstanceOverload("string_bsubmatch_string",
					[]*exprpb.Type{decls.String, decls.String},
					decls.NewMapType(decls.String, decls.String))),
			// N2: replaceAll —— xray output 赋值(如 workrelate 的
			// id: replaceAll(string(id1), "'", ""))依赖; cel-go v0.13 标准环境未提供, 需自声明。
			decls.NewFunction("replaceAll",
				decls.NewOverload("replaceAll_string_string_string",
					[]*exprpb.Type{decls.String, decls.String, decls.String},
					decls.String)),
			// N1: raw_header —— response.raw_header 的编译期兼容入口,
			// Evaluate 会在编译前把 response.raw_header 改写为该函数调用。
			decls.NewFunction("raw_header",
				decls.NewOverload("raw_header_response",
					[]*exprpb.Type{decls.NewObjectType("lib.Response")},
					decls.Bytes)),
		),
	}
	c.programOptions = []cel.ProgramOption{
		cel.Functions(
			&functions.Overload{
				Operator: "bytes_bcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					return types.Bool(bytes.Contains(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "string_bmatches_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bmatch", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bmatch", rhs.Type())
					}
					ok, err := regexp.Match(string(v1), v2)
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.Bool(ok)
				},
			},
			&functions.Overload{
				Operator: "md5_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to md5_string", value.Type())
					}
					return types.String(fmt.Sprintf("%x", md5.Sum([]byte(v))))
				},
			},
			&functions.Overload{
				Operator: "randomInt_int_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					from, ok := lhs.(types.Int)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to randomInt", lhs.Type())
					}
					to, ok := rhs.(types.Int)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to randomInt", rhs.Type())
					}
					min, max := int(from), int(to)
					return types.Int(rand.Intn(max-min) + min)
				},
			},
			&functions.Overload{
				Operator: "randomLowercase_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomLowercase", value.Type())
					}
					return types.String(randomLowercase(int(n)))
				},
			},
			&functions.Overload{
				Operator: "randomUppercase_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomUppercase", value.Type())
					}
					return types.String(randomUppercase(int(n)))
				},
			},
			&functions.Overload{
				Operator: "randomString_int",
				Unary: func(value ref.Val) ref.Val {
					n, ok := value.(types.Int)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to randomString", value.Type())
					}
					return types.String(randomString(int(n)))
				},
			},
			&functions.Overload{
				Operator: "base64_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_string", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString([]byte(v)))
				},
			},
			&functions.Overload{
				Operator: "base64_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64_bytes", value.Type())
					}
					return types.String(base64.StdEncoding.EncodeToString(v))
				},
			},
			&functions.Overload{
				Operator: "base64Decode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_string", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "base64Decode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to base64Decode_bytes", value.Type())
					}
					decodeBytes, err := base64.StdEncoding.DecodeString(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeBytes)
				},
			},
			&functions.Overload{
				Operator: "urlencode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_string", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urlencode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urlencode_bytes", value.Type())
					}
					return types.String(url.QueryEscape(string(v)))
				},
			},
			&functions.Overload{
				Operator: "urldecode_string",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.String)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_string", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "urldecode_bytes",
				Unary: func(value ref.Val) ref.Val {
					v, ok := value.(types.Bytes)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to urldecode_bytes", value.Type())
					}
					decodeString, err := url.QueryUnescape(string(v))
					if err != nil {
						return types.NewErr("%v", err)
					}
					return types.String(decodeString)
				},
			},
			&functions.Overload{
				Operator: "substr_string_int_int",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) == 3 {
						str, ok := values[0].(types.String)
						if !ok {
							return types.NewErr("invalid string to 'substr'")
						}
						start, ok := values[1].(types.Int)
						if !ok {
							return types.NewErr("invalid start to 'substr'")
						}
						length, ok := values[2].(types.Int)
						if !ok {
							return types.NewErr("invalid length to 'substr'")
						}
						runes := []rune(str)
						if start < 0 || length < 0 || int(start+length) > len(runes) {
							return types.NewErr("invalid start or length to 'substr'")
						}
						return types.String(runes[start : start+length])
					} else {
						return types.NewErr("too many arguments to 'substr'")
					}
				},
			},
			&functions.Overload{
				Operator: "reverse_wait_int",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					reverse, ok := lhs.Value().(*Reverse)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to 'wait'", lhs.Type())
					}
					timeout, ok := rhs.Value().(int64)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to 'wait'", rhs.Type())
					}
					return types.Bool(reverseCheck(reverse, timeout))
				},
			},
			&functions.Overload{
				Operator: "icontains_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to bcontains", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to bcontains", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(strings.Contains(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
				},
			},
			&functions.Overload{
				Operator: "tongda_date",
				Function: func(value ...ref.Val) ref.Val {
					return types.String(time.Now().Format("0601"))
				},
			},
			&functions.Overload{
				Operator: "shiro_key",
				Binary: func(key ref.Val, mode ref.Val) ref.Val {
					v1, ok := key.(types.String)
					if !ok {
						return types.ValOrErr(key, "unexpected type '%v' passed to shiro_key", key.Type())
					}
					v2, ok := mode.(types.String)
					if !ok {
						return types.ValOrErr(mode, "unexpected type '%v' passed to shiro_mode", mode.Type())
					}
					cookie := GetShrioCookie(string(v1), string(v2))
					if cookie == "" {
						return types.NewErr("%v", "key b64decode failed")
					}
					return types.String(cookie)
				},
			},
			&functions.Overload{
				Operator: "startsWith_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to startsWith_bytes", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to startsWith_bytes", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(bytes.HasPrefix(v1, v2))
				},
			},
			&functions.Overload{
				Operator: "startsWith_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to startsWith_string", lhs.Type())
					}
					v2, ok := rhs.(types.String)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to startsWith_string", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(strings.HasPrefix(strings.ToLower(string(v1)), strings.ToLower(string(v2))))
				},
			},
			&functions.Overload{
				Operator: "hexdecode",
				Unary: func(lhs ref.Val) ref.Val {
					v1, ok := lhs.(types.String)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to hexdecode", lhs.Type())
					}
					out, err := hex.DecodeString(string(v1))
					if err != nil {
						return types.ValOrErr(lhs, "hexdecode error: %v", err)
					}
					// 不区分大小写包含
					return types.Bytes(out)
				},
			},
			&functions.Overload{
				Operator: "bytes_ibcontains_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					v1, ok := lhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(lhs, "unexpected type '%v' passed to ibcontains", lhs.Type())
					}
					v2, ok := rhs.(types.Bytes)
					if !ok {
						return types.ValOrErr(rhs, "unexpected type '%v' passed to ibcontains", rhs.Type())
					}
					// 不区分大小写包含
					return types.Bool(bytes.Contains(bytes.ToLower(v1), bytes.ToLower(v2)))
				},
			},
			&functions.Overload{
				Operator: "string_bsubmatch_bytes",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					return bsubmatchFn(lhs, rhs)
				},
			},
			&functions.Overload{
				Operator: "string_bsubmatch_string",
				Binary: func(lhs ref.Val, rhs ref.Val) ref.Val {
					return bsubmatchFn(lhs, rhs)
				},
			},
			&functions.Overload{
				Operator: "replaceAll_string_string_string",
				Function: func(values ...ref.Val) ref.Val {
					if len(values) != 3 {
						return types.NewErr("replaceAll expects 3 arguments, got %d", len(values))
					}
					s, ok1 := values[0].(types.String)
					old, ok2 := values[1].(types.String)
					nw, ok3 := values[2].(types.String)
					if !ok1 || !ok2 || !ok3 {
						return types.NewErr("replaceAll expects (string, string, string)")
					}
					return types.String(strings.ReplaceAll(string(s), string(old), string(nw)))
				},
			},
			&functions.Overload{
				Operator: "raw_header_response",
				Unary: func(value ref.Val) ref.Val {
					resp, ok := value.Value().(*Response)
					if !ok {
						return types.ValOrErr(value, "unexpected type '%v' passed to raw_header", value.Type())
					}
					return types.Bytes(BuildRawHeader(resp.Headers))
				},
			},
		),
	}
	return c
}

// bsubmatchFn 实现 xray 的 '"regex".bsubmatch(target)': 用 Go 正则对响应体/原始头文本做
// 命名捕获提取, 返回 map<string,string>, 供 output 变量(如 search["name"])引用。
// 正则书写在 cel 字符串字面量里, 转义解析交给 cel; 未匹配到时返回错误 → 规则按 xray
// 语义判定失败(提取失败即不成立), 不会静默带空值继续往下走。
func bsubmatchFn(lhs ref.Val, rhs ref.Val) ref.Val {
	re, ok := lhs.(types.String)
	if !ok {
		return types.ValOrErr(lhs, "unexpected type '%v' passed to bsubmatch", lhs.Type())
	}
	var body string
	switch v := rhs.(type) {
	case types.Bytes:
		body = string(v)
	case types.String:
		body = string(v)
	default:
		return types.ValOrErr(rhs, "unexpected type '%v' passed to bsubmatch", rhs.Type())
	}
	r, err := regexp.Compile(string(re))
	if err != nil {
		return types.NewErr("bsubmatch invalid regex %q: %v", string(re), err)
	}
	m := r.FindStringSubmatch(body)
	if m == nil {
		return types.NewErr("bsubmatch: no match for regex %q", string(re))
	}
	names := r.SubexpNames()
	result := make(map[string]string, len(names))
	for i, name := range names {
		if i == 0 || name == "" || i >= len(m) {
			continue
		}
		result[name] = m[i]
	}
	return types.NewStringStringMap(types.DefaultTypeAdapter, result)
}

// 声明环境中的变量类型和函数
func (c *CustomLib) CompileOptions() []cel.EnvOption {
	return c.envOptions
}

func (c *CustomLib) ProgramOptions() []cel.ProgramOption {
	return c.programOptions
}

func (c *CustomLib) UpdateCompileOptions(args StrMap) {
	for _, item := range args {
		k, v := item.Key, item.Value
		// 在执行之前是不知道变量的类型的，所以统一声明为字符型
		// 所以randomInt虽然返回的是int型，在运算中却被当作字符型进行计算，需要重载string_*_string
		var d *exprpb.Decl
		if strings.HasPrefix(v, "randomInt") {
			d = decls.NewIdent(k, decls.Int, nil)
		} else if strings.HasPrefix(v, "newReverse") {
			d = decls.NewIdent(k, decls.NewObjectType("lib.Reverse"), nil)
		} else if isNumeric(v) {
			// 如果值是数字，声明为 double 类型（兼容 response.duration）
			d = decls.NewIdent(k, decls.Double, nil)
		} else {
			d = decls.NewIdent(k, decls.String, nil)
		}
		c.envOptions = append(c.envOptions, cel.Declarations(d))
	}
}

// declareOutputVars 把各规则 output 段出现的变量名预先声明进 cel 环境:
// 值形如 '"regex".bsubmatch(...)` 的提取表达式结果是 map<string,string>(output 里声明为
// search/search2 等), 其余形如 `search["group"]` / `replaceAll(...)` 的是字符串。
// 若不声明, output 表达式在编译期会报 "undeclared reference to 'search'" 之类错误。
// 与 set 变量同名的键跳过, 避免重复声明同一 ident。
func (c *CustomLib) declareOutputVars(p *Poc) {
	seen := make(map[string]struct{})
	for _, item := range p.Set {
		seen[item.Key] = struct{}{}
	}
	for _, item := range p.Sets {
		seen[item.Key] = struct{}{}
	}
	addRules := func(rules []Rules) {
		for _, rule := range rules {
			for _, item := range rule.Output {
				if _, ok := seen[item.Key]; ok {
					continue
				}
				seen[item.Key] = struct{}{}
				var d *exprpb.Decl
				if strings.Contains(item.Value, ".bsubmatch(") {
					d = decls.NewIdent(item.Key, decls.NewMapType(decls.String, decls.String), nil)
				} else {
					d = decls.NewIdent(item.Key, decls.String, nil)
				}
				c.envOptions = append(c.envOptions, cel.Declarations(d))
			}
		}
	}
	addRules(p.Rules)
	for _, group := range p.Groups {
		addRules(group.Value)
	}
}

// isNumeric 检查字符串是否为数字
func isNumeric(s string) bool {
	if s == "" {
		return false
	}
	// 尝试解析为整数
	if _, err := strconv.Atoi(s); err == nil {
		return true
	}
	// 尝试解析为浮点数
	if _, err := strconv.ParseFloat(s, 64); err == nil {
		return true
	}
	return false
}

// M2: 删除包级共享实例 `var randSource = rand.New(...)`——math/rand.Rand 不保证
// 并发安全, 而 randomLowercase/Uppercase/String 会被 check.go 的 CheckMultiPoc
// 多 worker 并发调用(POC set 变量生成盲注标记/临时文件名), 共享读写构成数据竞争,
// 随机序列不确定且标记值可能重复。
// 修法选 (a): 改用标准库包级 rand.Intn(顶层函数自带全局锁, 并发安全),
// 与本文件 randomInt(见 NewEnvOption 里 rand.Intn(max-min)+min)写法保持一致。
// RandomStr(*rand.Rand) 签名保留不动——check.go:516 每次调用自建局部 rand 仍在使用。
func randomLowercase(n int) string {
	return randomStrBy("abcdefghijklmnopqrstuvwxyz", n)
}

func randomUppercase(n int) string {
	return randomStrBy("ABCDEFGHIJKLMNOPQRSTUVWXYZ", n)
}

func randomString(n int) string {
	return randomStrBy("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", n)
}

// randomStrBy 用包级 rand(自带全局锁)从 letterBytes 中等概率取 n 个字符。
// 输出语义与原 RandomStr 逐项一致: 字符集相同、长度恒为 n、分布均匀;
// n<=0 或字符集为空时返回空串(原实现 n<=0 同样返回空串)。
func randomStrBy(letterBytes string, n int) string {
	if n <= 0 || len(letterBytes) == 0 {
		return ""
	}
	randBytes := make([]byte, n)
	for i := 0; i < n; i++ {
		randBytes[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(randBytes)
}

func reverseCheck(r *Reverse, timeout int64) bool {
	applyCeyeOverride() // 首次使用前应用 -ceye-key/-ceye-domain 覆盖(留空则保持内置默认)
	if ceyeApi == "" || r.Domain == "" || !common.DnsLog {
		return false
	}
	time.Sleep(time.Second * time.Duration(timeout))
	sub := strings.Split(r.Domain, ".")[0]
	urlStr := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", ceyeApi, sub)
	//fmt.Println(urlStr)
	req, _ := http.NewRequest("GET", urlStr, nil)
	resp, err := DoRequest(req, false)
	if err != nil {
		return false
	}

	if !bytes.Contains(resp.Body, []byte(`"data": []`)) && bytes.Contains(resp.Body, []byte(`"message": "OK"`)) { // api返回结果不为空
		//fmt.Println(urlStr) // 避免回显 API token（urlStr 含 token=<ceyeApi>），与上方 753 行同款调试打印一并注释
		return true
	}
	return false
}

func RandomStr(randSource *rand.Rand, letterBytes string, n int) string {
	const (
		letterIdxBits = 6                    // 6 bits to represent a letter index
		letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
		letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
		//letterBytes   = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	)
	randBytes := make([]byte, n)
	for i, cache, remain := n-1, randSource.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randSource.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			randBytes[i] = letterBytes[idx]
			i--
		}
		cache >>= letterIdxBits
		remain--
	}
	return string(randBytes)
}

func DoRequest(req *http.Request, redirect bool) (*Response, error) {
	if redirect {
		return doRequest(req, Client)
	}
	return doRequest(req, ClientNoRedirect)
}

// DoRequestWithTimeout 以显式超时发起请求; timeout<=0 时完全退化为 DoRequest,
// 即沿用 -wt(默认 5s) 的 Client/ClientNoRedirect, 普通 POC 行为不变。
// 时间盲注规则经 RuleTimeout 推导出所需超时后走这里, 只放大本次请求的 Timeout,
// Transport(代理/TLS/连接池)与原 client 共享。
func DoRequestWithTimeout(req *http.Request, redirect bool, timeout time.Duration) (*Response, error) {
	if timeout <= 0 {
		return DoRequest(req, redirect)
	}
	base := Client
	if !redirect {
		base = ClientNoRedirect
	}
	if base == nil {
		return DoRequest(req, redirect)
	}
	slow := *base // http.Client 无可变共享状态(Transport 为指针), 复制安全
	slow.Timeout = timeout
	return doRequest(req, &slow)
}

// durationThresholdRe 匹配表达式里时间盲注的判定阈值 response.duration >= X / > X,
// X 可以是数字字面量, 也可以是 set 变量(如 sleep_time)。
var durationThresholdRe = regexp.MustCompile(`response\.duration\s*(?:>=|>)\s*([0-9]+(?:\.[0-9]+)?|[A-Za-z_][A-Za-z0-9_]*)`)

// RuleTimeout 按规则表达式推导本次请求所需的超时秒数:
// 规则若用 response.duration >= X 判定, 而 -wt 总超时(默认 5s)会先一步打断请求,
// 这类时间盲注 POC(geoserver sleep 6s 等)必然失败。取 X*2+5s 缓冲并与 WebTimeout 取大;
// 倍数与缓冲均来自实测: 通达 setlaunch 的 SLEEP(5) 实测耗时 10.13s(该注入点被执行 2 次,
// 并非 5s), X+3(=8s) 与 X+5(=10s) 都小于 10.13 必然超时失败, 调到 -wt 20 才能命中;
// X*2 覆盖"注入被执行多次"的常见情况, +5 覆盖网络 RTT 与服务端执行开销。
// 表达式不含 duration 判定、或默认超时已足够时返回 0 → 走普通 client, 5s 行为不变。
// 上限 120s, 防止异常阈值把 worker 挂死。
func RuleTimeout(expression string, variableMap map[string]interface{}) time.Duration {
	maxSec := 0.0
	for _, m := range durationThresholdRe.FindAllStringSubmatch(expression, -1) {
		var sec float64
		if m[1] != "" && !isIdentifier(m[1]) {
			sec, _ = strconv.ParseFloat(m[1], 64)
		} else if raw, ok := variableMap[m[1]]; ok {
			// set 变量(如 sleep_time: 5)已在 evalset 中求值进 variableMap
			sec, _ = strconv.ParseFloat(fmt.Sprintf("%v", raw), 64)
		}
		if sec > maxSec {
			maxSec = sec
		}
	}
	if maxSec <= 0 {
		return 0
	}
	def := time.Duration(common.WebTimeout) * time.Second
	need := time.Duration(maxSec*float64(time.Second))*2 + 5*time.Second
	if need <= def {
		return 0
	}
	if need > 120*time.Second {
		need = 120 * time.Second
	}
	return need
}

// isIdentifier 判断阈值捕获是变量名(含字母/下划线开头)而非纯数字
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	c := s[0]
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func doRequest(req *http.Request, client *http.Client) (*Response, error) {
	start := time.Now() // 记录请求开始时间，用于时间盲注判断
	if req.Body == nil || req.Body == http.NoBody {
	} else {
		req.Header.Set("Content-Length", strconv.Itoa(int(req.ContentLength)))
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	oResp, err := client.Do(req)
	if err != nil {
		//fmt.Println("[-]DoRequest error: ",err)
		return nil, err
	}
	defer oResp.Body.Close()
	resp, err := ParseResponse(oResp)
	if resp != nil {
		resp.Duration = time.Since(start).Seconds() // 记录请求耗时（秒）
	}
	if err != nil {
		common.LogError("[-] ParseResponse error: " + err.Error())
		//return nil, err
	}
	return resp, err
}

func ParseUrl(u *url.URL) *UrlType {
	nu := &UrlType{}
	nu.Scheme = u.Scheme
	nu.Domain = u.Hostname()
	nu.Host = u.Host
	nu.Port = u.Port()
	nu.Path = u.EscapedPath()
	nu.Query = u.RawQuery
	nu.Fragment = u.Fragment
	return nu
}

func ParseRequest(oReq *http.Request) (*Request, error) {
	req := &Request{}
	req.Method = oReq.Method
	req.Url = ParseUrl(oReq.URL)
	header := make(map[string]string)
	for k := range oReq.Header {
		header[k] = oReq.Header.Get(k)
	}
	req.Headers = header
	req.ContentType = oReq.Header.Get("Content-Type")
	if oReq.Body == nil || oReq.Body == http.NoBody {
	} else {
		data, err := io.ReadAll(oReq.Body)
		if err != nil {
			return nil, err
		}
		req.Body = data
		oReq.Body = io.NopCloser(bytes.NewBuffer(data))
	}
	return req, nil
}

func ParseResponse(oResp *http.Response) (*Response, error) {
	var resp Response
	header := make(map[string]string)
	resp.Status = int32(oResp.StatusCode)
	resp.Url = ParseUrl(oResp.Request.URL)
	for k := range oResp.Header {
		header[k] = strings.Join(oResp.Header.Values(k), ";")
	}
	// cel-go 对 map 中不存在的键会报 "no such key" 错误而非返回空值, 而 Go net/http 已把
	// 响应头键规范化为 Canonical-MIME-Header-Key 形式(如 Content-Type/Set-Cookie/Location),
	// 部分 POC yml 却用小写键(如 content-type)索引导致求值报错且被静默吞掉。
	// 这里对每个键同时写入全小写形式, 使 canonical 与小写两种写法都能命中;
	// 键本身已无大小写差异时写入的是同一个键(值相同), 已存在的键不会被覆盖。
	for k, v := range header {
		lk := strings.ToLower(k)
		if _, ok := header[lk]; !ok {
			header[lk] = v
		}
	}
	resp.Headers = header
	resp.ContentType = oResp.Header.Get("Content-Type")
	body, _ := getRespBody(oResp)
	resp.Body = body
	return &resp, nil
}

// BuildRawHeader 把响应头拼成 response.raw_header 使用的文本, 格式 "Key: Value\r\n",
// 遍历时按 key 排序, 保证同一响应多次求值结果稳定。
// 必须说清的已知限制(有意为之): Go net/http 读取响应时已把 header 名规范化为
// Canonical-MIME-Header-Key(如 content-type→Content-Type), ParseResponse 又把同名多值
// 以 ";" 合并, 且 map 遍历本身丢失了线上原始顺序 —— 所以这不等于字节级的原始头。
// 但按现有 8 个引用 raw_header 的 POC(CVE-2022-26134/通达/泛微/用友NC×3 等)的用法,
// 只需要 bcontains / bsubmatch / ibcontains 在 "Key: Value\r\n" 文本上做包含或正则匹配,
// 以上限制均不影响命中; 这里不追求字节级还原。
// 另外 ParseResponse 为兼容小写索引会把每个键双写一份小写副本, 这里只输出 canonical 键, 避免重复。
func BuildRawHeader(header map[string]string) []byte {
	keys := make([]string, 0, len(header))
	for k := range header {
		if textproto.CanonicalMIMEHeaderKey(k) != k {
			continue // 小写兼容副本/非 canonical 形式的键, 跳过避免重复输出
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var buf strings.Builder
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteString(": ")
		buf.WriteString(header[k])
		buf.WriteString("\r\n")
	}
	return []byte(buf.String())
}

func getRespBody(oResp *http.Response) (body []byte, err error) {
	body, err = io.ReadAll(oResp.Body)
	if strings.Contains(oResp.Header.Get("Content-Encoding"), "gzip") {
		reader, err1 := gzip.NewReader(bytes.NewReader(body))
		if err1 == nil {
			body, err = io.ReadAll(reader)
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}
