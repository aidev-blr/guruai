// Cleaned and integrated chat.js tailored for chat2.html with fully styled table + text rendering (inline and multiline tables supported)

// --- DOM Elements ---
const subjectSelect = document.getElementById('subjectSelect');
const chapterSelect = document.getElementById('chapterSelect');
const literatureSelect = document.getElementById('literatureType');
const sendButton = document.getElementById('sendButton');
const userInput = document.getElementById('userQuestion');
const submitButton = document.getElementById('submitButton');
const chatArea = document.getElementById('chatArea');

// --- Append message to chat ---
function appendChatMessage(sender, message) {
  const messageDiv = document.createElement('div');
  messageDiv.className = `message ${sender}`;

  const bubble = document.createElement('div');
  bubble.className = `bubble ${sender}`;

  if (sender === 'bot') {
    const sections = message.split(/\n{2,}/g); // Split paragraphs or table blocks
    sections.forEach(section => {
      const content = section.trim();
      const element = formatAsTableOrText(content);
      bubble.appendChild(element);
    });
  } else {
    bubble.textContent = message;
  }

  messageDiv.appendChild(bubble);
  chatArea.appendChild(messageDiv);
  chatArea.scrollTop = chatArea.scrollHeight;
  return messageDiv;
}

function formatText(text) {
  if (!text) return '';
  return text
    .replace(/###(.*?)(\n|$)/g, '<u><strong>$1</strong></u>$2')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/\n{2,}/g, '</p><p>')
    .replace(/\n/g, '<br>');
}

function formatAsTableOrText(content) {
  const lines = content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.includes('|') && !/^(\|\s*:?-+:?\s*)+\|?$/.test(line)); // Skip markdown separators

  const isTable = lines.length >= 2 && lines.every(line => line.split('|').length >= 2);

  if (isTable) {
    const table = document.createElement('table');
    table.style.borderCollapse = 'collapse';
    table.style.width = '100%';
    table.style.margin = '1em 0';

    lines.forEach((line, index) => {
      const row = document.createElement('tr');
      const cells = line.split('|').map(cell => cell.trim()).filter(Boolean); // Remove empty cells

      cells.forEach(cellText => {
        const cell = document.createElement(index === 0 ? 'th' : 'td');
        cell.innerHTML = formatText(cellText);
        cell.style.border = '1px solid #ccc';
        cell.style.padding = '8px';
        cell.style.textAlign = 'left';
        cell.style.verticalAlign = 'top';
        row.appendChild(cell);
      });

      if (index === 0) {
        const thead = document.createElement('thead');
        thead.appendChild(row);
        table.appendChild(thead);
      } else {
        if (!table.querySelector('tbody')) {
          table.appendChild(document.createElement('tbody'));
        }
        table.querySelector('tbody').appendChild(row);
      }
    });

    const wrapper = document.createElement('div');
    wrapper.className = 'table-container';
    wrapper.appendChild(table);
    return wrapper;
  } else {
    const para = document.createElement('p');
    para.innerHTML = formatText(content);
    return para;
  }
}



// --- Submit Path and Load PDF ---
submitButton.addEventListener('click', async () => {
  const board = localStorage.getItem('board');
 

  const classLevel = localStorage.getItem('class');
  console.log("Loaded class:", classLevel);``
  document.getElementById('displayClass').textContent = classLevel;

  const subject = subjectSelect.value;
  const chapter = chapterSelect.value;
  const literatureType = (subject.toLowerCase() === 'english') ? literatureSelect.value : '';

  if (!subject || !chapter) {
    alert('Please select both subject and chapter');
    return;
  }

  let path = `gs://rag-project-storagebucket/${board}/Class ${classLevel}/${subject}`;
  if (subject.toLowerCase() === 'english') {
    path += `/${literatureType}`;
  }
  path += `/${chapter.replace(/ /g, '_').replace(/[()]/g, '')}.pdf`;

  const loadingMsg = appendChatMessage('bot', '📄 Loading PDF...');

  try {
    const res = await fetch('/api/chat/submit-path', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path })
    });

    const data = await res.json();

    if (data.status === 'success') {
      userInput.disabled = false;
      loadingMsg.querySelector('.bubble').textContent = '✅ PDF loaded successfully. You can now ask your questions.';
      // alert('Material loaded successfully!');
    } else {
      throw new Error(data.message || 'Unknown error');
    }
  } catch (err) {
    console.error('Submit error:', err);
    loadingMsg.querySelector('.bubble').textContent = `❌ Failed to load material: ${err.message}`;
    alert('Failed to load material');
  }
});

// --- Send Question ---
sendButton.addEventListener('click', sendMessage);
userInput.addEventListener('keypress', (e) => {
  if (e.key === 'Enter') sendMessage();
});

async function sendMessage() {
  const question = userInput.value.trim();
  if (!question) return;

  const board = localStorage.getItem('board');
  const classLevel = localStorage.getItem('class');
  const subject = subjectSelect.value;
  const chapter = chapterSelect.value;
  const literatureType = (subject.toLowerCase() === 'english') ? literatureSelect.value : '';

  if (!subject || !chapter) {
    appendChatMessage("bot", "❗ Please load study material first.");
    return;
  }

  const path = `gs://rag-project-storagebucket/${board}/Class ${classLevel}/${subject}${subject.toLowerCase() === 'english' ? '/' + literatureType : ''}/${chapter.replace(/ /g, '_').replace(/[()]/g, '')}.pdf`;

  appendChatMessage("user", question);
  userInput.value = '';
  const loadingMsg = appendChatMessage("bot", "🤖 Thinking...");

  try {
    const res = await fetch('/api/chat/ask', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question, path })
    });

    const data = await res.json();
    const reply = data.answer || "❓ I couldn't find an answer.";
    loadingMsg.querySelector('.bubble').innerHTML = '';
    appendChatMessage('bot', reply);
  } catch (err) {
    console.error('Error:', err);
    loadingMsg.querySelector('.bubble').textContent = '⚠️ Error fetching answer.';
  }
}
