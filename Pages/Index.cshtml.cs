using Microsoft.AspNetCore.Mvc.RazorPages;

namespace DotnetCity.Cryptography.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ICrypto _crypto;
        public string MsgEncrypted { get; set; }
        public string MsgDecrypted { get; set; }
        public IndexModel(ICrypto crypto)
        {
            _crypto = crypto;
        }
        public void OnGet()
        {
            MsgEncrypted = _crypto.Encrypt("string to be encrypted","super","secret");
            MsgDecrypted = _crypto.Decrypt("5DB24AB49A2FCFD5F9141982A2FD6DBF53EDF9360DB9CE9614FBEB0D62CA876E", "super", "secret");
        }
    }
}