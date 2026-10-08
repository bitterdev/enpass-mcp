/* Author: Fabian Bitter (fabian@bitter.de) */
//
// Keeps new entries clean the way the vault owner wants them: a readable title, no run or ticket
// log in title, subtitle or note, and key material as an attachment instead of note text.
// Returns the list of problems; an empty list means the entry may be written.

const TICKET = /\bJUNO-\d+\b/i;
const PEM = /-----BEGIN [A-Z0-9 ]*(PRIVATE KEY|CERTIFICATE)-----/;

export function entryProblems({ title = "", subtitle = "", note = "", custom = [] } = {}) {
  const problems = [];
  if (title.includes("·")) problems.push("title contains a middle dot, use a plain title like 'Auth0 (fonella)'");
  for (const [name, text] of [["title", title], ["subtitle", subtitle], ["note", note]]) {
    if (TICKET.test(text)) problems.push(`${name} contains a ticket number, keep run and ticket notes out of the vault`);
  }
  if (PEM.test(note) || PEM.test(subtitle)) problems.push("key or certificate in the text, store it as an attachment (add_attachment)");
  for (const f of custom) {
    if (PEM.test(String(f.value ?? ""))) problems.push(`field "${f.label}" holds a key or certificate, store it as an attachment`);
    if (TICKET.test(`${f.label ?? ""} ${f.value ?? ""}`)) problems.push(`field "${f.label}" contains a ticket number, keep run and ticket notes out of the vault`);
  }
  return problems;
}
