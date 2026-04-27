const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({ headless: 'new' });
  const page = await browser.newPage();
  
  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err.message));
  page.on('requestfailed', request => console.log('REQ FAILED:', request.url(), request.failure().errorText));

  console.log('Navigating to http://localhost:8080/');
  await page.goto('http://localhost:8080/');
  
  console.log('Waiting for network idle...');
  await page.waitForNetworkIdle();
  
  console.log('Clicking "Detection Rules"...');
  // Find the button with text "Detection Rules"
  const buttons = await page.$$('.nav-btn');
  for (const btn of buttons) {
    const text = await page.evaluate(el => el.textContent, btn);
    if (text.includes('Detection Rules')) {
      await btn.click();
      break;
    }
  }

  await new Promise(r => setTimeout(r, 2000));
  console.log('Done.');
  await browser.close();
})();
