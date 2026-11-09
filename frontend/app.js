(function () {
  'use strict';

  const checkForm = document.getElementById('check-form');
  const passwordInput = document.getElementById('password');
  const togglePassword = document.getElementById('toggle-password');
  const clearCheck = document.getElementById('clear-check');
  const useExample = document.getElementById('use-example');
  const checkResult = document.getElementById('check-result');

  const composeForm = document.getElementById('compose-form');
  const wordInput = document.getElementById('word');
  const digitsInput = document.getElementById('digits');
  const composeButton = document.getElementById('compose-button');
  const composeMessage = document.getElementById('compose-message');
  const composeResults = document.getElementById('compose-results');
  const toggleGenerated = document.getElementById('toggle-generated');
  const clearGenerated = document.getElementById('clear-generated');
  const symbolButtons = Array.from(document.querySelectorAll('.symbol'));

  const progress = document.querySelector('.scroll-progress');
  const header = document.querySelector('.site-header');

  let checkBusy = false;
  let composeBusy = false;
  let generatedHidden = false;

  const LIMITS = 'No breach match does not guarantee safety. The password was only absent from the breach data checked here. It can still be guessed, reused, or exposed somewhere else.';

  function setResult(node, title, body, tone, extra) {
    node.className = 'result ' + tone;
    node.replaceChildren();
    const heading = document.createElement('p');
    heading.className = 'result-title';
    heading.textContent = title;
    const copy = document.createElement('p');
    copy.textContent = body;
    node.append(heading, copy);
    if (extra) {
      const meta = document.createElement('p');
      meta.className = 'meta';
      meta.textContent = extra;
      node.append(meta);
    }
  }

  function selectedSpecials() {
    return symbolButtons
      .filter((button) => button.getAttribute('aria-pressed') === 'true')
      .map((button) => button.textContent.trim());
  }

  function wantedCount() {
    const selected = composeForm.querySelector('input[name="keep"]:checked');
    const count = Number(selected ? selected.value : 4);
    if (count === 3 || count === 5) return count;
    return 4;
  }

  async function sha1Hex(value) {
    const bytes = new TextEncoder().encode(value);
    const digest = await crypto.subtle.digest('SHA-1', bytes);
    let hex = '';
    const view = new Uint8Array(digest);
    for (let index = 0; index < view.length; index += 1) {
      hex += view[index].toString(16).padStart(2, '0');
    }
    return hex.toUpperCase();
  }

  async function queryRanges(prefixes) {
    let response;
    try {
      response = await fetch('/api/range', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({ prefixes: prefixes }),
        cache: 'no-store'
      });
    } catch (error) {
      throw new Error('The local app could not be reached. Keep this page on http://localhost:3000 while npm start is running.');
    }

    let payload = null;
    try {
      payload = await response.json();
    } catch (error) {
      payload = null;
    }

    if (!response.ok) {
      throw new Error((payload && payload.error) || 'The breach check did not complete.');
    }
    if (!payload || !payload.ranges || typeof payload.ranges !== 'object') {
      throw new Error('The breach response was incomplete. Nothing was marked clear.');
    }
    return payload.ranges;
  }

  function countFor(ranges, hash) {
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const bucket = ranges[prefix];
    if (!bucket || typeof bucket !== 'object') {
      throw new Error('The breach response was incomplete. Nothing was marked clear.');
    }
    const count = bucket[suffix];
    return Number.isInteger(count) ? count : 0;
  }

  async function lookupPasswords(passwords) {
    const hashed = [];
    for (const password of passwords) {
      const hash = await sha1Hex(password);
      hashed.push({ password: password, hash: hash });
    }
    const prefixes = [];
    hashed.forEach((item) => {
      const prefix = item.hash.slice(0, 5);
      if (!prefixes.includes(prefix)) prefixes.push(prefix);
    });
    const ranges = await queryRanges(prefixes);
    return hashed.map((item) => ({
      password: item.password,
      prefix: item.hash.slice(0, 5),
      count: countFor(ranges, item.hash)
    }));
  }

  function secureInt(max) {
    if (!Number.isInteger(max) || max <= 0) {
      throw new Error('Invalid random range.');
    }
    const limit = Math.floor(0x100000000 / max) * max;
    const buffer = new Uint32Array(1);
    let value = 0;
    do {
      crypto.getRandomValues(buffer);
      value = buffer[0];
    } while (value >= limit);
    return value % max;
  }

  function pick(list) {
    return list[secureInt(list.length)];
  }

  function shuffle(list) {
    const copy = list.slice();
    for (let index = copy.length - 1; index > 0; index -= 1) {
      const swap = secureInt(index + 1);
      const held = copy[index];
      copy[index] = copy[swap];
      copy[swap] = held;
    }
    return copy;
  }

  function applyCase(word) {
    const chars = Array.from(word).map((character) => {
      const lower = character.toLowerCase();
      return lower >= 'a' && lower <= 'z' ? lower : character;
    });
    const indexes = [];
    chars.forEach((character, index) => {
      if (character >= 'a' && character <= 'z') indexes.push(index);
    });
    if (!indexes.length) return chars.join('');
    let flips = 1 + secureInt(indexes.length);
    if (flips === indexes.length && indexes.length > 1) flips -= 1;
    shuffle(indexes).slice(0, flips).forEach((index) => {
      chars[index] = chars[index].toUpperCase();
    });
    return chars.join('');
  }

  function randomTail(specials) {
    const parts = [pick(specials), String(secureInt(10))];
    return secureInt(2) === 0 ? parts[0] + parts[1] : parts[1] + parts[0];
  }

  function buildVariation(word, numbers, specials) {
    const cased = applyCase(word);
    const first = pick(specials);
    const second = pick(specials);
    const tail = randomTail(specials);
    const splitAt = 1 + secureInt(Math.max(1, Array.from(cased).length - 1));
    const characters = Array.from(cased);
    const styles = [
      () => cased + first + numbers + second + tail,
      () => numbers + first + cased + second + tail,
      () => characters.slice(0, splitAt).join('') + first + numbers + second + characters.slice(splitAt).join('') + tail,
      () => first + cased + second + numbers + tail,
      () => cased + numbers + first + second + tail
    ];
    let password = styles[secureInt(styles.length)]();
    while (password.length < 16) password += String(secureInt(10));
    return password;
  }

  function accepts(password, word, numbers, specials) {
    if (password.length < 16 || password.length > 80) return false;
    if (!/[a-z]/.test(password) || !/[A-Z]/.test(password)) return false;
    if (!password.includes(numbers)) return false;
    if (!specials.some((symbol) => password.includes(symbol))) return false;
    const folded = password.toLowerCase();
    return folded.includes(word.toLowerCase());
  }

  function validateRecipe(word, numbers, specials) {
    if (word.length < 3 || word.length > 24) {
      return 'Use a memorable word of 3 to 24 characters.';
    }
    const letters = word.match(/[A-Za-z]/g) || [];
    if (letters.length < 3) return 'Include at least 3 letters in the memorable word.';
    if (!/^[0-9]{1,8}$/.test(numbers)) return 'Enter 1 to 8 digits.';
    if (!specials.length) return 'Select at least one special character.';
    return '';
  }

  async function collectClearPasswords(word, numbers, specials, wanted) {
    const accepted = [];
    const seen = new Set();
    let checked = 0;
    let matched = 0;

    for (let round = 0; round < 4 && accepted.length < wanted; round += 1) {
      const batch = [];
      let guard = 0;
      while (batch.length < (wanted - accepted.length) * 2 && guard < 60) {
        guard += 1;
        const candidate = buildVariation(word, numbers, specials);
        if (seen.has(candidate) || !accepts(candidate, word, numbers, specials)) continue;
        seen.add(candidate);
        batch.push(candidate);
      }
      if (!batch.length) break;
      const results = await lookupPasswords(batch);
      checked += results.length;
      results.forEach((result) => {
        if (result.count > 0) {
          matched += 1;
          return;
        }
        if (accepted.length < wanted) accepted.push(result.password);
      });
    }

    return { passwords: accepted, checked: checked, matched: matched };
  }

  function showGenerated(passwords) {
    composeResults.replaceChildren();
    passwords.forEach((password, index) => {
      const row = document.createElement('div');
      row.className = 'candidate';
      const field = document.createElement('input');
      field.type = generatedHidden ? 'password' : 'text';
      field.readOnly = true;
      field.value = password;
      field.spellcheck = false;
      field.setAttribute('aria-label', 'Generated password ' + (index + 1));
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'button quiet';
      copy.textContent = 'Copy';
      copy.addEventListener('click', () => copyPassword(field, copy));
      row.append(field, copy);
      composeResults.append(row);
    });
    const hasRows = passwords.length > 0;
    toggleGenerated.hidden = !hasRows;
    clearGenerated.hidden = !hasRows;
  }

  async function copyPassword(field, button) {
    const value = field.value;
    let copied = false;
    try {
      await navigator.clipboard.writeText(value);
      copied = true;
    } catch (error) {
      const previous = field.type;
      field.type = 'text';
      field.focus();
      field.select();
      copied = document.execCommand('copy');
      field.type = previous;
    }
    button.textContent = copied ? 'Copied' : 'Copy failed';
    window.setTimeout(() => {
      button.textContent = 'Copy';
    }, 1600);
  }

  function setPasswordVisible(visible) {
    passwordInput.type = visible ? 'text' : 'password';
    togglePassword.setAttribute('aria-pressed', visible ? 'true' : 'false');
    togglePassword.setAttribute('aria-label', visible ? 'Hide password' : 'Show password');
    togglePassword.querySelector('.eye-open').hidden = visible;
    togglePassword.querySelector('.eye-shut').hidden = !visible;
  }

  function setGeneratedVisible(visible) {
    generatedHidden = !visible;
    composeResults.querySelectorAll('input').forEach((field) => {
      field.type = visible ? 'text' : 'password';
    });
    toggleGenerated.textContent = visible ? 'Hide passwords' : 'Show passwords';
    toggleGenerated.setAttribute('aria-pressed', visible ? 'false' : 'true');
  }

  function clearGeneratedPasswords() {
    composeResults.replaceChildren();
    toggleGenerated.hidden = true;
    clearGenerated.hidden = true;
    generatedHidden = false;
    toggleGenerated.textContent = 'Hide passwords';
    setResult(
      composeMessage,
      'Generated passwords removed',
      'The variations were cleared from this page. They were not saved.',
      'idle'
    );
  }

  async function runCheck(password) {
    if (checkBusy) return;
    if (!password) {
      setResult(checkResult, 'Enter a password', 'Type a password, then run the check again.', 'error');
      passwordInput.focus();
      return;
    }
    if (password.length > 256) {
      setResult(checkResult, 'That password is too long', 'Use 256 characters or fewer.', 'error');
      return;
    }
    if (!crypto.subtle) {
      setResult(checkResult, 'This browser cannot hash locally', 'Open the page in a current browser on http://localhost:3000.', 'error');
      return;
    }

    checkBusy = true;
    checkForm.setAttribute('aria-busy', 'true');
    setResult(checkResult, 'Checking the hash prefix', 'The password is being hashed on this page. Only the first 5 hash characters will be sent.', 'wait');

    try {
      const result = (await lookupPasswords([password]))[0];
      const sent = 'Only the hash prefix ' + result.prefix + ' was sent. The rest of the hash stayed in this page.';
      if (result.count > 0) {
        setResult(
          checkResult,
          'Found in breach data',
          'This password has been seen ' + result.count.toLocaleString() + ' times in the Have I Been Pwned password corpus. Stop using it.',
          'hit',
          sent
        );
      } else {
        setResult(
          checkResult,
          'No breach match',
          LIMITS,
          'clear',
          sent
        );
      }
    } catch (error) {
      setResult(checkResult, 'The check did not finish', error.message, 'error');
    } finally {
      checkBusy = false;
      checkForm.removeAttribute('aria-busy');
    }
  }

  async function runCompose(event) {
    event.preventDefault();
    if (composeBusy) return;
    const word = wordInput.value.trim();
    const numbers = digitsInput.value.trim();
    const specials = selectedSpecials();
    const problem = validateRecipe(word, numbers, specials);
    if (problem) {
      setResult(composeMessage, 'Check the ingredients', problem, 'error');
      return;
    }
    if (!crypto.subtle) {
      setResult(composeMessage, 'This browser cannot generate securely', 'Open the page in a current browser on http://localhost:3000.', 'error');
      return;
    }

    const wanted = wantedCount();
    composeBusy = true;
    composeForm.setAttribute('aria-busy', 'true');
    composeButton.disabled = true;
    showGenerated([]);
    setResult(
      composeMessage,
      'Building and checking variations',
      'Each candidate is hashed locally. Only hash prefixes are sent, and matches are discarded.',
      'wait'
    );

    try {
      const outcome = await collectClearPasswords(word, numbers, specials, wanted);
      showGenerated(outcome.passwords);
      if (!outcome.passwords.length) {
        setResult(
          composeMessage,
          'No clear variation this pass',
          'Every variation checked in this pass matched known breach data, so none are shown. Try a less common word or different digits. ' + LIMITS,
          'hit',
          'Checked ' + outcome.checked + '. Matched and discarded ' + outcome.matched + '.'
        );
      } else {
        const shortfall = outcome.passwords.length < wanted
          ? ' Fewer than requested were clear in this pass.'
          : '';
        setResult(
          composeMessage,
          outcome.passwords.length + ' with no breach match',
          'These candidates were not found in the breach data. ' + LIMITS + shortfall,
          'clear',
          'Checked ' + outcome.checked + '. Discarded ' + outcome.matched + ' with a breach match.'
        );
      }
    } catch (error) {
      showGenerated([]);
      setResult(composeMessage, 'The generator stopped', error.message + ' Unchecked passwords were not shown.', 'error');
    } finally {
      composeBusy = false;
      composeForm.removeAttribute('aria-busy');
      composeButton.disabled = false;
    }
  }

  togglePassword.addEventListener('click', () => {
    setPasswordVisible(passwordInput.type === 'password');
  });

  passwordInput.addEventListener('input', () => {
    if (!checkBusy && !checkResult.classList.contains('idle')) {
      setResult(checkResult, 'Results appear here', 'The password changed, so the previous result was cleared.', 'idle');
    }
  });

  checkForm.addEventListener('submit', (event) => {
    event.preventDefault();
    runCheck(passwordInput.value);
  });

  clearCheck.addEventListener('click', () => {
    passwordInput.value = '';
    setPasswordVisible(false);
    setResult(checkResult, 'Cleared', 'The password field is empty. Nothing from it was saved.', 'idle');
    passwordInput.focus();
  });

  useExample.addEventListener('click', () => {
    passwordInput.value = 'password';
    setPasswordVisible(false);
    runCheck(passwordInput.value);
  });

  symbolButtons.forEach((button) => {
    button.addEventListener('click', () => {
      const on = button.getAttribute('aria-pressed') !== 'true';
      button.setAttribute('aria-pressed', on ? 'true' : 'false');
      button.classList.toggle('is-on', on);
    });
  });

  composeForm.addEventListener('submit', runCompose);

  toggleGenerated.addEventListener('click', () => {
    setGeneratedVisible(generatedHidden);
  });

  clearGenerated.addEventListener('click', clearGeneratedPasswords);

  digitsInput.addEventListener('input', () => {
    const cleaned = digitsInput.value.replace(/\D/g, '').slice(0, 8);
    if (cleaned !== digitsInput.value) digitsInput.value = cleaned;
  });

  function onScroll() {
    header.classList.toggle('is-scrolled', window.scrollY > 8);
    const max = document.documentElement.scrollHeight - window.innerHeight;
    const ratio = max > 0 ? window.scrollY / max : 0;
    progress.style.transform = 'scaleX(' + ratio + ')';
  }

  window.addEventListener('scroll', onScroll, { passive: true });
  onScroll();
}());
