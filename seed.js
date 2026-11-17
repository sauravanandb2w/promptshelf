// Original starter prompts, inserted once when the prompts table is empty.
const SAMPLES = [
  ['writing', 'Rewrite for a clearer, shorter version', 'Cut a draft by a target length without losing meaning.', ['editing', 'concise'],
    'You are a careful editor. Rewrite the text below in about {{target_words}} words for {{audience}}.\nKeep every factual claim. Replace jargon with plain words. Use short sentences and active voice.\nReturn only the rewritten text, then a one-line list of what you removed.\n\nText:\n{{text}}'],
  ['writing', 'Blog post outline with a point of view', 'Outline that argues something instead of listing facts.', ['blog', 'outline'],
    'Create an outline for a blog post on "{{topic}}" for {{audience}}.\nStart with a one-sentence thesis that takes a clear position. Give 4-6 sections, each with a heading and two bullets of evidence or examples the writer should include.\nEnd with a call to action. Flag any section where the writer must supply their own data.'],
  ['coding', 'Code review with severity labels', 'Structured review that separates bugs from style.', ['review', 'quality'],
    'Review the {{language}} code below. List findings under three headings: Bugs, Risks, Style.\nFor each finding give: line or function, why it matters, and a minimal fix. Label each finding High, Medium or Low.\nIf there are no bugs, say so. Do not rewrite the whole file.\n\nCode:\n{{code}}'],
  ['coding', 'Explain an error and propose a fix', 'Turns a stack trace into a cause and a patch.', ['debugging', 'errors'],
    'Here is an error from a {{stack}} project:\n{{error_message}}\n\nRelevant code:\n{{code}}\n\nExplain the most likely root cause in two sentences. Then give the smallest change that fixes it, as a diff. List one other possible cause and how to check it.'],
  ['coding', 'Write unit tests for a function', 'Edge-case focused test generation.', ['testing', 'unit-tests'],
    'Write unit tests for the function below using {{test_framework}}.\nCover: normal input, empty or null input, boundary values, and invalid input. One behavior per test, descriptive test names.\nDo not change the function. If its behavior is unclear, list your assumptions first.\n\n{{function_code}}'],
  ['marketing', 'Landing page headline variants', 'Ten headlines in distinct angles.', ['copywriting', 'landing-page'],
    'Write 10 headline options for a landing page for {{product}}, aimed at {{audience}}.\nGroup them by angle: benefit, pain point, curiosity, proof, urgency. Max 10 words each.\nAfter the list, pick the strongest two and say why in one sentence each.'],
  ['marketing', 'Product launch email', 'Short launch email with subject line options.', ['email', 'launch'],
    'Write a launch email for {{product}} to {{audience}}.\nGive 3 subject lines under 50 characters. Body under 150 words: one problem, one solution, one proof point, one button label. Tone: {{tone}}.\nNo exclamation marks and no filler openers.'],
  ['business', 'Meeting notes to action items', 'Extract owners, deadlines and decisions.', ['meetings', 'summary'],
    'From the meeting notes below, produce: 1) Decisions made, 2) Action items as a table with Owner, Task, Due date, 3) Open questions.\nIf an owner or date is missing, write "unassigned" or "no date". Do not invent details.\n\nNotes:\n{{notes}}'],
  ['business', 'One-page decision memo', 'Options, tradeoffs and a recommendation.', ['memo', 'decision'],
    'Write a one-page decision memo on: {{decision}}.\nSections: Context (3 sentences), Options (2-3, each with pros, cons, cost), Recommendation with the single biggest reason, Risks and how to reduce them, Next step this week.\nUse only the facts I give you; mark gaps as "needs data".\n\nFacts:\n{{facts}}'],
  ['education', 'Explain a concept at three levels', 'Same idea for a child, a student and an expert.', ['explainer', 'learning'],
    'Explain {{concept}} three times: for a 10-year-old (analogy, under 60 words), for a first-year university student (define terms, one example), and for a practitioner (nuances, common mistakes).\nEnd with two questions I can ask myself to check I understood.'],
  ['productivity', 'Weekly plan from a messy task list', 'Turn a brain dump into a realistic week.', ['planning', 'tasks'],
    'Here is my task list: {{tasks}}\nI have {{hours_per_day}} focused hours per day, Monday to Friday. Group tasks, estimate time for each, and schedule them by day.\nPut the most important task first each day. Leave 20% buffer. List what you would drop if the week is too full.'],
  ['image-generation', 'Product photo scene description', 'Detailed prompt for an image model.', ['product', 'photography'],
    'A studio photo of {{product}} on {{surface}}, soft window light from the left, shallow depth of field, 50mm lens look, muted {{color_palette}} background, subtle shadow, no text, no people, high detail.'],
  ['data-analysis', 'Analyze a CSV and report findings', 'Plain-language summary with caveats.', ['csv', 'insights'],
    'You are a data analyst. I will paste a CSV. First list the columns and what you think each means. Then report: 3 notable patterns, 1 anomaly, and the questions this data cannot answer.\nGive numbers with the column they come from. State any assumption you make.\n\nCSV:\n{{csv_data}}'],
];

module.exports = function seed(db, bcrypt, now) {
  if (db.prepare('SELECT COUNT(*) c FROM prompts').get().c > 0) return;
  let sys = db.prepare("SELECT id FROM users WHERE email='system@promptshelf.local'").get();
  if (!sys) {
    const id = db.prepare('INSERT INTO users(email,name,pass_hash,role,created) VALUES(?,?,?,?,?)')
      .run('system@promptshelf.local', 'PromptShelf', bcrypt.hashSync(require('crypto').randomBytes(24).toString('hex'), 10), 'user', now()).lastInsertRowid;
    sys = { id };
  }
  const ins = db.prepare('INSERT INTO prompts(title,description,body,category,tags,author_id,status,created) VALUES(?,?,?,?,?,?,?,?)');
  db.transaction(() => SAMPLES.forEach((s, i) => ins.run(s[1], s[2], s[4], s[0], JSON.stringify(s[3]), sys.id, 'approved', now() - i * 1000)))();
};
