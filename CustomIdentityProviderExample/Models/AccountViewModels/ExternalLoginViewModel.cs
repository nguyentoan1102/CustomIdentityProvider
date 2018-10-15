using System.ComponentModel.DataAnnotations;

namespace CustomIdentityProviderExample.Models.AccountViewModels
{
    public class ExternalLoginViewModel
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
    }
}
