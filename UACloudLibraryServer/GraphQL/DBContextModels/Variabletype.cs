﻿
namespace UACloudLibrary.DbContextModels
{
    public partial class Variabletype
    {
        public int Variabletype_id { get; set; }
 
        public long Nodeset_id { get; set; }
        
        public string Variabletype_BrowseName { get; set; }
        
        public string Variabletype_Value { get; set; }
        
        public string Variabletype_Namespace { get; set; }
    }
}
