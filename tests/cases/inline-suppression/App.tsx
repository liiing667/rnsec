export function load() {
  // rnsec-ignore: INSECURE_HTTP_URL legacy partner endpoint, tracked in SEC-12
  fetch('http://partner.example-corp.com/a');
  fetch('http://partner.example-corp.com/b');
  fetch('http://partner.example-corp.com/c'); // rnsec-ignore: NO_REQUEST_TIMEOUT

  // Directive-shaped text inside a string is not a comment: the finding survives.
  const fakeLineComment = '// rnsec-ignore: INSECURE_HTTP_URL';
  fetch('http://partner.example-corp.com/string');

  // The same applies to template literals, including multi-line ones.
  const fakeBlockComment = `/* rnsec-ignore: INSECURE_HTTP_URL */`;
  fetch('http://partner.example-corp.com/template');

  // A block comment ends at its closing delimiter; the next line is not suppressed.
  /* rnsec-ignore: INSECURE_HTTP_URL
     rationale wrapped across lines
  */
  fetch('http://partner.example-corp.com/after-block');

  // Malformed directives (no explicit, well-formed rule ID) never suppress anything.
  // rnsec-ignore:
  fetch('http://partner.example-corp.com/malformed');
}
