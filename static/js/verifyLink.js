function verifyLink(linkId, appId, verificationLink) {
  const button = document.querySelector(`#verifyButton_${linkId}`);
  
  button.disabled = true;
  const apiUrl = `/dashboard/link/${linkId}/verify`;

  fetch(apiUrl)
    .then(response => {
      if (!response.ok) {
        throw new Error('Network response was not ok');
      }
      return response.json();
    })
    .then(data => {
      if (data.udontownthis){
        alert('U own dont that link stupid');
      }
      else if (data.is_ratelimit) {
        alert('The the api is ratelimted please try again later.');
      }
      else if (data.is_valid) {
        alert('The link is valid.');
      } else {
        alert(`The link is not valid. Please change the redirect uri on https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Authentication/appId/${appId}/isMSAApp~/true to ${verificationLink}`);
      }
    })
    .catch(error => {
      console.error('There was a problem with the fetch operation:', error);
      alert('An error occurred while verifying the link.');
    }).finally(() => {
      button.disabled = false;
    });
}
