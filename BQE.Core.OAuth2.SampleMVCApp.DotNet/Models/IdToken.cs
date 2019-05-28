using Newtonsoft.Json;
using System.Collections.Generic;

namespace BQE.Core.OAuth2.SampleMVCApp.DotNet.Models
{
    public class IdTokenHeader
    {
        [JsonProperty("kid")]
        public string Kid { get; set; }


        [JsonProperty("alg")]
        public string Alg { get; set; }
    }

    public class IdTokenPayload
    {
        [JsonProperty("sub")]
        public string Sub { get; set; }


        [JsonProperty("aud")]
        public string Aud { get; set; }  //public List<string> Aud { get; set; }


        [JsonProperty("companyId")]
        public string CompanyId { get; set; } 


        [JsonProperty("auth_time")]
        public string Auth_time { get; set; }


        [JsonProperty("iss")]
        public string Iss { get; set; }


        [JsonProperty("exp")]
        public string Exp { get; set; }


        [JsonProperty("iat")]
        public string Iat { get; set; }

        [JsonProperty("nbf")]
        public string Nbf { get; set; }

        [JsonProperty("at_hash")]
        public string At_Hash { get; set; }

        [JsonProperty("sid")]
        public string Sid { get; set; }

        [JsonProperty("idp")]
        public string Idp { get; set; }
    }

    
}