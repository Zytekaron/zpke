/**
 * Copyright (c) 2024 Michael Thornes
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Single-file library
 *
 * Version: 1 (2024/08/24)
 */

package ckhpke

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"math/bits"
	"strconv"
	"strings"
)

type INI struct {
	INIMap

	Sections map[string]INIMap
}

func NewINI() *INI {
	return &INI{
		INIMap:   INIMap{},
		Sections: map[string]INIMap{},
	}
}

func (i *INI) Section(name string) INIMap {
	m, ok := i.Sections[name]
	if ok {
		return m
	}

	m = INIMap{}
	i.Sections[name] = m
	return m
}

func (i *INI) MaybeSection(name string) (INIMap, bool) {
	m, ok := i.Sections[name]
	return m, ok
}

func (i *INI) WriteTo(w io.Writer) (n int64, err error) {
	nw, err := w.Write([]byte(i.String()))
	return int64(nw), err
}

func (i *INI) Bytes() []byte {
	var buf bytes.Buffer

	for k, v := range i.INIMap {
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(v)
		buf.WriteString("\n")
	}

	// disable print ahead for the first section when there are
	// no globals (\n separator between globals and sections)
	shouldPrintAhead := len(i.INIMap) > 0

	for name, section := range i.Sections {
		if shouldPrintAhead {
			buf.WriteString("\n")
		}
		buf.WriteString("[")
		buf.WriteString(name)
		buf.WriteString("]\n")
		for k, v := range section {
			buf.WriteString(k)
			buf.WriteString(" = ")
			buf.WriteString(v)
			buf.WriteString("\n")
		}
		shouldPrintAhead = true
	}

	return buf.Bytes()
}

func (i *INI) String() string {
	return string(i.Bytes())
}

type INIParser struct {
	scanner     *bufio.Scanner
	line        int
	inSection   bool
	sectionName string
}

func NewINIParser(r io.Reader) *INIParser {
	return &INIParser{
		scanner: bufio.NewScanner(r),
	}
}

func NewINIParserFromScanner(scanner *bufio.Scanner) *INIParser {
	return &INIParser{
		scanner: scanner,
	}
}

func (p *INIParser) Parse() (*INI, error) {
	ini := NewINI()

	for p.scanner.Scan() {
		line := strings.TrimSpace(p.scanner.Text())
		if line == "" {
			continue
		}

		// check for and begin sections

		leftBracket := strings.HasPrefix(line, "[")
		rightBracket := strings.HasSuffix(line, "]")
		if leftBracket {
			if !rightBracket {
				return ini, fmt.Errorf("invalid section '%s'", line)
			}

			name := line[1 : len(line)-2]
			if name == "" {
				return ini, fmt.Errorf("invalid section name '%s'", name)
			}

			p.inSection = true
			p.sectionName = name
			ini.Sections[name] = map[string]string{}
			continue
		}

		// split key and value

		split := strings.SplitN(line, "=", 2)
		if len(split) != 2 {
			return ini, fmt.Errorf("key-value line missing equals '%s'", line)
		}

		key := strings.TrimSpace(split[0])
		value := strings.TrimSpace(split[1])

		// write pair to globals or current section

		if p.inSection {
			ini.Sections[p.sectionName][key] = value
		} else {
			ini.INIMap[key] = value
		}
	}

	return ini, nil
}

type INIMap map[string]string

func (i INIMap) Get(key string) string {
	return i[key]
}

func (i INIMap) GetDefault(key, def string) string {
	str, ok := i[key]
	if !ok {
		return def
	}
	return str
}

func (i INIMap) Set(key, value string) {
	i[key] = value
}

func (i INIMap) Int(key string) (int, error) {
	return strconv.Atoi(i[key])
}

func (i INIMap) IntDefault(key string, def int) (int, error) {
	if _, ok := i[key]; !ok {
		return def, nil
	}
	return i.Int(key)
}

func (i INIMap) SetInt(key string, value int) {
	i[key] = strconv.Itoa(value)
}

func (i INIMap) Int32(key string) (int32, error) {
	n, err := strconv.ParseInt(i[key], 10, 32)
	return int32(n), err
}

func (i INIMap) Int32Default(key string, def int32) (int32, error) {
	if _, ok := i[key]; !ok {
		return def, nil
	}
	return i.Int32(key)
}

func (i INIMap) SetInt32(key string, value int32) {
	i[key] = strconv.FormatInt(int64(value), 10)
}

func (i INIMap) Int64(key string) (int64, error) {
	return strconv.ParseInt(i[key], 10, 64)
}

func (i INIMap) Int64Default(key string, def int64) (int64, error) {
	if _, ok := i[key]; !ok {
		return def, nil
	}
	return i.Int64(key)
}

func (i INIMap) SetInt64(key string, value int64) {
	i[key] = strconv.FormatInt(value, 10)
}

func (i INIMap) Uint(key string) (uint, error) {
	n, err := strconv.ParseUint(i[key], 10, bits.UintSize)
	return uint(n), err
}

func (i INIMap) UintDefault(key string, def uint) (uint, error) {
	if _, ok := i[key]; !ok {
		return def, nil
	}
	return i.Uint(key)
}

func (i INIMap) SetUint(key string, value uint) {
	i[key] = strconv.FormatUint(uint64(value), 10)
}

func (i INIMap) Uint32(key string) (uint32, error) {
	n, err := strconv.ParseUint(i[key], 10, 32)
	return uint32(n), err
}

func (i INIMap) Uint32Default(key string, def uint32) (uint32, error) {
	if _, ok := i[key]; !ok {
		return def, nil
	}
	return i.Uint32(key)
}

func (i INIMap) SetUint32(key string, value uint32) {
	i[key] = strconv.FormatUint(uint64(value), 10)
}

func (i INIMap) Uint64(key string) (uint64, error) {
	return strconv.ParseUint(i[key], 10, 64)
}

func (i INIMap) Uint64Default(key string, def uint64) (uint64, error) {
	if _, ok := i[key]; !ok {
		return def, nil
	}
	return i.Uint64(key)
}

func (i INIMap) SetUint64(key string, value uint64) {
	i[key] = strconv.FormatUint(value, 10)
}

func (i INIMap) Float32(key string) (float32, error) {
	f, err := strconv.ParseFloat(i[key], 32)
	return float32(f), err
}

func (i INIMap) GetFloat32(key string, def float32) (float32, error) {
	if _, ok := i[key]; !ok {
		return def, nil
	}
	return i.Float32(key)
}

func (i INIMap) SetFloat32(key string, value float32) {
	i[key] = strconv.FormatFloat(float64(value), 'f', -1, 10)
}

func (i INIMap) Float64(key string) (float64, error) {
	return strconv.ParseFloat(i[key], 32)
}

func (i INIMap) GetFloat64(key string, def float64) (float64, error) {
	if _, ok := i[key]; !ok {
		return def, nil
	}
	return i.Float64(key)
}

func (i INIMap) SetFloat64(key string, value float64) {
	i[key] = strconv.FormatFloat(value, 'f', -1, 10)
}

func (i INIMap) BigInt(key string) (*big.Int, bool) {
	n := &big.Int{}
	_, ok := n.SetString(i[key], 10)
	return n, ok
}

func (i INIMap) BigIntDefault(key string, def *big.Int) (*big.Int, bool) {
	if _, ok := i[key]; !ok {
		return def, true
	}
	return i.BigInt(key)
}

func (i INIMap) BigFloat(key string) (*big.Float, bool) {
	n := &big.Float{}
	_, ok := n.SetString(i[key])
	return n, ok
}

func (i INIMap) BigFloatDefault(key string, def *big.Float) (*big.Float, bool) {
	if _, ok := i[key]; !ok {
		return def, true
	}
	return i.BigFloat(key)
}

func (i INIMap) ParseHex(key string) ([]byte, error) {
	return hex.DecodeString(i[key])
}

func (i INIMap) SetHex(key string, value []byte) {
	i[key] = hex.EncodeToString(value)
}

func (i INIMap) GetBase64(key string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(i[key])
}

func (i INIMap) SetBase64(key string, value []byte) {
	i[key] = base64.StdEncoding.EncodeToString(value)
}

func (i INIMap) GetBase64Raw(key string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(i[key])
}

func (i INIMap) SetBase64Raw(key string, value []byte) {
	i[key] = base64.RawStdEncoding.EncodeToString(value)
}

func (i INIMap) GetBase64URL(key string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(i[key])
}

func (i INIMap) SetBase64URL(key string, value []byte) {
	i[key] = base64.URLEncoding.EncodeToString(value)
}

func (i INIMap) GetBase64RawURL(key string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(i[key])
}

func (i INIMap) SetBase64RawURL(key string, value []byte) {
	i[key] = base64.RawURLEncoding.EncodeToString(value)
}
