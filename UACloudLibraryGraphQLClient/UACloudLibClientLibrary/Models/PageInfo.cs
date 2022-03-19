﻿/* ========================================================================
 * Copyright (c) 2005-2021 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

namespace UACloudLibClientLibrary
{
    using Newtonsoft.Json;
    using System.Collections.Generic;

    /// <summary>
    /// Contains a List of T, the total count of T available and if a next and/or previous page is available
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class PageInfo<T> where T : class
    {
        [JsonProperty("edges")]
        public List<PageItem<T>> Items { get; set; }

        [JsonProperty("pageInfo")]
        public PageBools Page { get; set; }

        [JsonProperty("totalCount")]
        public int TotalCount { get; set; }

        public PageInfo()
        {
            Items = new List<PageItem<T>>();
            Page = new PageBools();
            TotalCount = 0;
        }
    }
    /// <summary>
    /// Contains the data if a next and/or previous page is available
    /// </summary>
    public class PageBools
    {
        [JsonProperty("hasNextPage")]
        public bool hasNext { get; set; }

        [JsonProperty("hasPreviousPage")]
        public bool hasPrev { get; set; }
    }
}
