function namemc(accId) {
    const button = document.querySelector(`#namemcButton`);
    
    button.disabled = true;
  
    fetch(`/dashboard/acc/${accId}/namemc`)
      .then(response => {
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        return response.json();
      })
      .then(data => {
        if (data.udontownthis){
          alert('U own dont that account stupid');
        }
        else if (data.link == "") {
          alert('couldnt get link');
        }
        else {
            alert(`the name mc link is ${data.link}`);
        }
      })
      .catch(error => {
        console.error('There was a problem with the fetch operation:', error);
        alert('An error occurred while verifying the link.');
      }).finally(() => {
        button.disabled = false;
      });
  }
  