// Adapted from templUI v1.13.2; MIT notices are retained below.
// Source: https://github.com/templui/templui/blob/75ff269e4b13e65e2ebc973835dea91e1112cca1/utils/templui.go
// Local changes: retain only TwMerge. The upstream class merger
// stays pinned to github.com/Oudwins/tailwind-merge-go v0.2.0.
//
// BEGIN THIRD-PARTY NOTICES
// MIT License
//
// Copyright (c) 2023 Axel Adrian (templUI)
// Copyright (c) 2024 Oudwin (tailwind-merge-go)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
// END THIRD-PARTY NOTICES
package utils

import twmerge "github.com/Oudwins/tailwind-merge-go"

// TwMerge combines Tailwind classes and resolves conflicts.
// Example: "bg-red-500 hover:bg-blue-500", "bg-green-500" → "hover:bg-blue-500 bg-green-500"
func TwMerge(classes ...string) string {
	return twmerge.Merge(classes...)
}
