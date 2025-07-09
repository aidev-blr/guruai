// Global DOM Element References
const boardOptions = document.getElementById('board-options');
const classOptions = document.getElementById('class-options');
const subjectOptions = document.getElementById('subject-options');
const chapterSelectContainer = document.getElementById('chapter-select-container'); // This wraps chapter options
const chapterSelectionDisplay = document.getElementById('chapter-selection-display'); // This is the span that shows selected chapter name
const chapterOptions = document.getElementById('chapter-options'); // This is the div where chapter buttons are placed

const boardMessage = document.getElementById('board-message');
const classMessage = document.getElementById('class-message');
const subjectMessage = document.getElementById('subject-message');
const chapterMessage = document.getElementById('chapter-message');

const submitButton = document.getElementById('submitButton');
const userQuestionInput = document.getElementById('userQuestion');
const sendButton = document.getElementById('sendButton');
const chatArea = document.getElementById('chatArea');
const historyContainer = document.getElementById('history-container'); // If you have a history section

const displayBoard = document.getElementById('displayBoard');
const displayClass = document.getElementById('displayClass');
const userName = document.getElementById('user-name');


// State Object to track selections
const state = {
    board: null,
    class: null, // This will store values like "Class 10"
    subject: null,
    chapter: null, // This will store the actual chapter ID (e.g., "Chapter 1")
    chapterDisplayName: null, // This will store the descriptive name (e.g., "Real Numbers")
    literatureType: null, // For English subject
    stream: 'NA' // Default stream, will be updated by user data
};

// Map of descriptive chapter names for each board, class, and subject
// This must be comprehensive for all your content

const classSubjectChapterNames = {
    "NCERT": {
        "Class 6": {
            "Maths": {
    "Chapter 1": "Patterns in Mathematics",
    "Chapter 2": "Lines and Angles",
    "Chapter 3": "Number Play",
    "Chapter 4": "Data Handling and Presentation",
    "Chapter 5": "Prime Time",
    "Chapter 6": "Perimeter and Area",
    "Chapter 7": "Fractions",
    "Chapter 8": "Playing with Constructions",
    "Chapter 9": "Symmetry",
    "Chapter 10": "The Other Side of Zero"
}
,
            "Science": {
    "Chapter 1": "The Wonderful World of Science",
    "Chapter 2": "Diversity in the Living World",
    "Chapter 3": "Mindful Eating: A Path to a Healthy Body",
    "Chapter 4": "Exploring Magnets",
    "Chapter 5": "Measurement of Length and Motion",
    "Chapter 6": "Materials Around Us",
    "Chapter 7": "Temperature and its Measurement",
    "Chapter 8": "A Journey through States of Water",
    "Chapter 9": "Methods of Separation in Everyday Life",
    "Chapter 10": "Living Creatures: Exploring their Characteristics",
    "Chapter 11": "Nature’s Treasures",
    "Chapter 12": "Beyond Earth"
}
,
            "English": {
    "Chapter 1": "Fables and Folk Tales",
    "Chapter 2": "Friendship",
    "Chapter 3": "Nurturing Nature",
    "Chapter 4": "Sports and Wellness",
    "Chapter 5": "Culture and Tradition"
},
"Social": {
    "Chapter 1": "Locating Places on the Earth",
    "Chapter 2": "Oceans and Continents",
    "Chapter 3": "Landforms and Life",
    "Chapter 4": "Timeline and Sources of History",
    "Chapter 5": "India, That Is Bharat",
    "Chapter 6": "The Beginnings of Indian Civilisation",
    "Chapter 7": "India’s Cultural Roots",
    "Chapter 8": "Unity in Diversity, or ‘Many in the One’",
    "Chapter 9": "Family and Community",
    "Chapter 10": "Grassroots Democracy — Part 1: Governance",
    "Chapter 11": "Grassroots Democracy — Part 2: Local Government in Rural Areas",
    "Chapter 12": "Grassroots Democracy — Part 3: Local Government in Urban Areas",
    "Chapter 13": "The Value of Work",
    "Chapter 14": "Economic Activities Around Us"
}
},
        "Class 7": {
            "Maths": {
    "Chapter 1": "Large Numbers Around Us",
    "Chapter 2": "Arithmetic Expressions",
    "Chapter 3": "A Peek Beyond the Point",
    "Chapter 4": "Expressions using Letter-Numbers",
    "Chapter 5": "Parallel and Intersecting Lines",
    "Chapter 6": "Number Play",
    "Chapter 7": "A Tale of Three Intersecting Lines",
    "Chapter 8": "Working with Fractions"
}
,
            "Science": {
    "Chapter 1": "The Ever-Evolving World of Science",
    "Chapter 2": "Exploring Substances: Acidic, Basic, and Neutral",
    "Chapter 3": "Electricity: Circuits and Their Components",
    "Chapter 4": "The World of Metals and Non-metals",
    "Chapter 5": "Changes Around Us: Physical and Chemical",
    "Chapter 6": "Adolescence: A Stage of Growth and Change",
    "Chapter 7": "Heat Transfer in Nature",
    "Chapter 8": "Measurement of Time and Motion",
    "Chapter 9": "Life Processes in Animals",
    "Chapter 10": "Life Processes in Plants",
    "Chapter 11": "Light: Shadows and Reflections",
    "Chapter 12": "Earth, Moon, and the Sun"
}
,
            "English": {
    "Chapter 1": "Learning Together",
    "Chapter 2": "Wit and Humour",
    "Chapter 3": "Dreams and Discoveries",
    "Chapter 4": "Travel and Adventure",
    "Chapter 5": "Bravehearts"
},
"Social": {
    "Chapter 1": "Geographical Diversity of India",
    "Chapter 2": "Understanding the Weather",
    "Chapter 3": "Climates of India",
    "Chapter 4": "New Beginnings: Cities and States",
    "Chapter 5": "The Rise of Empires",
    "Chapter 6": "The Age of Reorganisation",
    "Chapter 7": "The Gupta Era: An Age of Tireless Creativity",
    "Chapter 8": "How the Land Becomes Sacred",
    "Chapter 9": "From the Rulers to the Ruled: Types of Governments",
    "Chapter 10": "The Constitution of India — An Introduction",
    "Chapter 11": "From Barter to Money",
    "Chapter 12": "Understanding Markets"
}
},
"Class 8":{
    "Maths": {
    "Chapter 1": "Rational Numbers",
    "Chapter 2": "Linear Equations in One Variable",
    "Chapter 3": "Understanding Quadrilaterals",
    "Chapter 4": "Practical Geometry",
    "Chapter 5": "Data Handling",
    "Chapter 6": "Squares and Square Roots",
    "Chapter 7": "Cubes and Cube Roots",
    "Chapter 8": "Comparing Quantities",
    "Chapter 9": "Algebraic Expressions and Identities",
    "Chapter 10": "Visualising Solid Shapes",
    "Chapter 11": "Mensuration",
    "Chapter 12": "Exponents and Powers",
    "Chapter 13": "Direct and Inverse Proportions",
    "Chapter 14": "Factorisation",
    "Chapter 15": "Introduction to Graphs",
    "Chapter 16": "Playing with Numbers"
},
"Science": {
    "Chapter 1": "The Ever-Evolving World of Science",
    "Chapter 2": "Exploring Substances: Acidic, Basic, and Neutral",
    "Chapter 3": "Electricity: Circuits and Their Components",
    "Chapter 4": "The World of Metals and Non-metals",
    "Chapter 5": "Changes Around Us: Physical and Chemical",
    "Chapter 6": "Adolescence: A Stage of Growth and Change",
    "Chapter 7": "Heat Transfer in Nature",
    "Chapter 8": "Measurement of Time and Motion",
    "Chapter 9": "Life Processes in Animals",
    "Chapter 10": "Life Processes in Plants",
    "Chapter 11": "Light: Shadows and Reflections",
    "Chapter 12": "Earth, Moon, and the Sun"
},
"English": {
    "literature": {
        "Chapter 1": "The Best Christmas Present in the World",
        "Chapter 2": "The Tsunami",
        "Chapter 3": "Glimpses of the Past",
        "Chapter 4": "Bepin Choudhury’s Lapse of Memory",
        "Chapter 5": "The Summit Within",
        "Chapter 6": "This is Jody’s Fawn",
        "Chapter 7": "A Visit to Cambridge",
        "Chapter 8": "A Short Monsoon Diary" 
    },
    "supplementary": {
        "Chapter 1": "How the Camel Got His Hump",
        "Chapter 2": "Children at Work",
        "Chapter 3": "The Selfish Giant",
        "Chapter 4": "A Visit to the Circus",
        "Chapter 5": "Princess September",
        "Chapter 6": "The Treasure Within",
        "Chapter 7": "The Comet – I",
        "Chapter 8": "The Comet – II"
    }
},
"History": {
    "Chapter 1": "How, When and Where",
    "Chapter 2": "From Trade to Territory",
    "Chapter 3": "Ruling the Countryside",
    "Chapter 4": "Tribals, Dikus and the Vision of a Golden Age",
    "Chapter 5": "When People Rebel",
    "Chapter 6": "Civilising the 'Native', Educating the Nation",
    "Chapter 7": "Women, Caste and Reform",
    "Chapter 8": "The Making of the National Movement: 1870s – 1947"
},
"Geography": {
    "Chapter 1": "Resources",
    "Chapter 2": "Land, Soil, Water, Natural Vegetation and Wildlife Resources",
    "Chapter 3": "Agriculture",
    "Chapter 4": "Industries",
    "Chapter 5": "Human Resources"
},
"Civics": {
    "Chapter 1": "The Indian Constitution",
    "Chapter 2": "Understanding Secularism",
    "Chapter 3": "Parliament and the Making of Laws",
    "Chapter 4": "Judiciary",
    "Chapter 5": "Understanding Marginalisation",
    "Chapter 6": "Confronting Marginalisation",
    "Chapter 7": "Public Facilities",
    "Chapter 8": "Law and Social Justice"
}
},
"Class 9":{
    "Maths":{
    "Chapter 1": "Number Systems",
    "Chapter 2": "Polynomials",
    "Chapter 3": "Coordinate Geometry",
    "Chapter 4": "Linear Equations in Two Variables",
    "Chapter 5": "Introduction to Euclid’s Geometry",
    "Chapter 6": "Lines and Angles",
    "Chapter 7": "Triangles",
    "Chapter 8": "Quadrilaterals",
    "Chapter 9": "Circles",
    "Chapter 10": "Heron’s Formula",
    "Chapter 11": "Surface Areas and Volumes",
    "Chapter 12": "Statistics"
},
"Science":{
    "Chapter 1": "Matter in Our Surroundings",
    "Chapter 2": "Is Matter Around Us Pure?",
    "Chapter 3": "Atoms and Molecules",
    "Chapter 4": "Structure of the Atom",
    "Chapter 5": "The Fundamental Unit of Life",
    "Chapter 6": "Tissues",
    "Chapter 7": "Motion",
    "Chapter 8": "Force and Laws of Motion",
    "Chapter 9": "Gravitation",
    "Chapter 10": "Work and Energy",
    "Chapter 11": "Sound",
    "Chapter 12": "Improvement in Food Resources"
},
"History": {
    "Chapter 1": "The French Revolution",
    "Chapter 2": "Socialism in Europe and the Russian Revolution",
    "Chapter 3": "Nazism and the Rise of Hitler",
    "Chapter 4": "Forest Society and Colonialism",
    "Chapter 5": "Pastoralists in the Modern World"
},
"Geography": {
    "Chapter 1": "India – Size and Location",
    "Chapter 2": "Physical Features of India",
    "Chapter 3": "Drainage",
    "Chapter 4": "Climate",
    "Chapter 5": "Natural Vegetation and Wildlife",
    "Chapter 6": "Population"
},
"English":{
    "literature":{
        "Chapter 1": "The Fun They Had",
    "Chapter 2": "The Sound of Music",
    "Chapter 3": "The Little Girl",
    "Chapter 4": "A Truly Beautiful Mind",
    "Chapter 5": "The Snake and the Mirror",
    "Chapter 6": "My Childhood",
    "Chapter 7": "Reach for the Top",
    "Chapter 8": "Kathmandu",
    "Chapter 9": "If I Were You"
    },
    "supplementary":{
    "Chapter 1": "The Lost Child",
    "Chapter 2": "The Adventures of Toto",
    "Chapter 3": "Iswaran the Storyteller",
    "Chapter 4": "In the Kingdom of Fools",
    "Chapter 5": "The Happy Prince",
    "Chapter 6": "Weathering the Storm in Ersama",
    "Chapter 7": "The Last Leaf",
    "Chapter 8": "A House is Not a Home",
    "Chapter 9": "The Beggar"
    }
},
"Economics": {
    "Chapter 1": "The Story of Village Palampur",
    "Chapter 2": "People as Resource",
    "Chapter 3": "Poverty as a Challenge",
    "Chapter 4": "Food Security in India"
},
"Civics": {
    "Chapter 1": "What is Democracy? Why Democracy?",
    "Chapter 2": "Constitutional Design",
    "Chapter 3": "Electoral Politics",
    "Chapter 4": "Working of Institutions",
    "Chapter 5": "Democratic Rights"
}
},
"Class 10":{
    "Maths": {
    "Chapter 1": "Real Numbers",
    "Chapter 2": "Polynomials",
    "Chapter 3": "Pair of Linear Equations in Two Variables",
    "Chapter 4": "Quadratic Equations",
    "Chapter 5": "Arithmetic Progressions",
    "Chapter 6": "Triangles",
    "Chapter 7": "Coordinate Geometry",
    "Chapter 8": "Introduction to Trigonometry",
    "Chapter 9": "Some Applications of Trigonometry",
    "Chapter 10": "Circles",
    "Chapter 11": "Areas Related to Circles",
    "Chapter 12": "Surface Areas and Volumes",
    "Chapter 13": "Statistics",
    "Chapter 14": "Probability"
},
"Science": {
    "Chapter 1": "Chemical Reactions and Equations",
    "Chapter 2": "Acids, Bases, and Salts",
    "Chapter 3": "Metals and Non-Metals",
    "Chapter 4": "Carbon and Its Compounds",
    "Chapter 5": "Life Processes",
    "Chapter 6": "Control and Coordination",
    "Chapter 7": "How Do Organisms Reproduce?",
    "Chapter 8": "Heredity",
    "Chapter 9": "Light – Reflection and Refraction",
    "Chapter 10": "The Human Eye and the Colourful World",
    "Chapter 11": "Electricity",
    "Chapter 12": "Magnetic Effects of Electric Current",
    "Chapter 13": "Our Environment"
},
"History": {
    "Chapter 1": "The Rise of Nationalism in Europe",
    "Chapter 2": "Nationalism in India",
    "Chapter 3": "The Making of a Global World",
    "Chapter 4": "The Age of Industrialisation",
    "Chapter 5": "Print Culture and the Modern World"
},
"Geography": {
  "Chapter 1": "Resources and Development",
  "Chapter 2": "Forest and Wildlife Resources",
  "Chapter 3": "Water Resources",
  "Chapter 4": "Agriculture",
  "Chapter 5": "Minerals and Energy Resources",
  "Chapter 6": "Manufacturing Industries",
  "Chapter 7": "Lifelines of National Economy"
},
"English":{
    "literature":{
    "Chapter 1": "A Letter to God",
    "Chapter 2": "Nelson Mandela: Long Walk to Freedom",
    "Chapter 3": "Two Stories about Flying",
    "Chapter 4": "From the Diary of Anne Frank",
    "Chapter 5": "Glimpses of India",
    "Chapter 6": "Mijbil the Otter",
    "Chapter 7": "Madam Rides the Bus",
    "Chapter 8": "The Sermon at Benares",
    "Chapter 9": "The Proposal"
    },
    "supplementary":{
    "Chapter 1": "A Triumph of Surgery",
    "Chapter 2": "The Thief’s Story",
    "Chapter 3": "The Midnight Visitor",
    "Chapter 4": "A Question of Trust",
    "Chapter 5": "Footprints without Feet",
    "Chapter 6": "The Making of a Scientist",
    "Chapter 7": "The Necklace",
    "Chapter 8": "Bholi",
    "Chapter 9": "The Book That Saved the Earth"
    }
},
"Economics": {
  "Chapter 1": "Development",
  "Chapter 2": "Sectors of the Indian Economy",
  "Chapter 3": "Money and Credit",
  "Chapter 4": "Globalisation and the Indian Economy",
  "Chapter 5": "Consumer Rights"
},
"Civics": {
  "Chapter 1": "Power Sharing",
  "Chapter 2": "Federalism",
  "Chapter 3": "Gender, Religion and Caste",
  "Chapter 4": "Political Parties",
  "Chapter 5": "Outcomes of Democracy"
}
},
"Class 11":{
    "English":{
        
      "Chapter 1": "The Portrait of a Lady",
      "Chapter 2": "We're Not Afraid to Die... if We Can All Be Together",
      "Chapter 3": "Discovering Tut: The Saga Continues",
      "Chapter 4": "Landscape of the Soul",
      "Chapter 5": "The Ailing Planet: The Green Movement's Role",
      "Chapter 6": "The Browning Version",
      "Chapter 7": "The Adventure",
      "Chapter 8": "Silk Road"
        },
        "Biology": {
  "Chapter 1": "The Living World",
  "Chapter 2": "Biological Classification",
  "Chapter 3": "Plant Kingdom",
  "Chapter 4": "Animal Kingdom",
  "Chapter 5": "Morphology of Flowering Plants",
  "Chapter 6": "Anatomy of Flowering Plants",
  "Chapter 7": "Structural Organisation in Animals",
  "Chapter 8": "Cell: The Unit of Life",
  "Chapter 9": "Biomolecules",
  "Chapter 10": "Cell Cycle and Cell Division",
  "Chapter 11": "Photosynthesis in Higher Plants",
  "Chapter 12": "Respiration in Plants",
  "Chapter 13": "Plant Growth and Development",
  "Chapter 14": "Breathing and Exchange of Gases",
  "Chapter 15": "Body Fluids and Circulation",
  "Chapter 16": "Excretory Products and Their Elimination",
  "Chapter 17": "Locomotion and Movement",
  "Chapter 18": "Neural Control and Coordination",
  "Chapter 19": "Chemical Coordination and Integration"
},
"Chemistry-Part1": {
  "Chapter 1": "Some Basic Concepts of Chemistry",
  "Chapter 2": "Structure of Atom",
  "Chapter 3": "Classification of Elements and Periodicity in Properties",
  "Chapter 4": "Chemical Bonding and Molecular Structure",
  "Chapter 5": "Thermodynamics",
  "Chapter 6": "Equilibrium"
},
"Chemistry-Part2": {
  "Chapter 1": "Redox Reactions",
  "Chapter 2": "Organic Chemistry – Some Basic Principles and Techniques",
  "Chapter 3": "Hydrocarbons"
},
"Maths": {
    "Chapter 1": "Sets",
    "Chapter 2": "Relations and Functions",
    "Chapter 3": "Trigonometric Functions",
    "Chapter 4": "Complex Numbers and Quadratic Equations",
    "Chapter 5": "Linear Inequalities",
    "Chapter 6": "Permutations and Combinations",
    "Chapter 7": "Binomial Theorem",
    "Chapter 8": "Sequences and Series",
    "Chapter 9": "Straight Lines",
    "Chapter 10": "Conic Sections",
    "Chapter 11": "Introduction to Three-Dimensional Geometry",
    "Chapter 12": "Limits and Derivatives",
    "Chapter 13": "Statistics",
    "Chapter 14": "Probability"
},
"Physics-Part1": {
  "Chapter 1": "Units and Measurements",
  "Chapter 2": "Motion in a Straight Line",
  "Chapter 3": "Motion in a Plane",
  "Chapter 4": "Laws of Motion",
  "Chapter 5": "Work, Energy and Power",
  "Chapter 6": "System of Particles and Rotational Motion",
  "Chapter 7": "Gravitation"
},
"Physics-Part2": {
  "Chapter 1": "Mechanical Properties of Solids",
  "Chapter 2": "Mechanical Properties of Fluids",
  "Chapter 3": "Thermal Properties of Matter",
  "Chapter 4": "Thermodynamics",
  "Chapter 5": "Kinetic Theory",
  "Chapter 6": "Oscillations",
  "Chapter 7": "Waves"
}
    ,
        "Business Studies": {
    "Chapter 1": "Business, Trade and Commerce",
    "Chapter 2": "Forms of Business Organisation",
    "Chapter 3": "Private, Public and Global Enterprises",
    "Chapter 4": "Business Services",
    "Chapter 5": "Emerging Modes of Business",
    "Chapter 6": "Social Responsibilities of Business and Business Ethics",
    "Chapter 7": "Formation of a Company",
    "Chapter 8": "Sources of Business Finance",
    "Chapter 9": "Small Business and Entrepreneurship",
    "Chapter 10": "Internal Trade",
    "Chapter 11": "International Business"
  },
  "Financial accounting-Part1": {
    "Chapter 1": "Introduction to Accounting",
    "Chapter 2": "Theory Base of Accounting",
    "Chapter 3": "Recording of Transactions I",
    "Chapter 4": "Recording of Transactions II",
    "Chapter 5": "Bank Reconciliation Statement",
    "Chapter 6": "Trial Balance and Rectification of Errors",
    "Chapter 7": "Depreciation, Provisions and Reserves"
  },
  "Financial accounting-Part2 ": {
    "Chapter 8": "Financial Statements I",
    "Chapter 9": "Financial Statements II"
  }

},
"Class 12":{
    "English":{
        "literature":{
        "Chapter 1": "The Last Lesson",
      "Chapter 2": "Lost Spring",
      "Chapter 3": "Deep Water",
      "Chapter 4": "The Rattrap",
      "Chapter 5": "Indigo",
      "Chapter 6": "Poets and Pancakes",
      "Chapter 7": "The Interview",
      "Chapter 8": "Going Places"
        },
        "supplementary":{
     "Chapter 1": "The Third Level",
    "Chapter 2": "The Tiger King",
    "Chapter 3": "Journey to the End of the Earth",
    "Chapter 4": "The Enemy",
    "Chapter 5": "On the Face of It",
    "Chapter 6": "Memories of Childhood"
        }
    },
   
  "Biology": {
    "Chapter 1": "Sexual Reproduction in Flowering Plants",
    "Chapter 2": "Human Reproduction",
    "Chapter 3": "Reproductive Health",
    "Chapter 4": "Principles of Inheritance and Variation",
    "Chapter 5": "Molecular Basis of Inheritance",
    "Chapter 6": "Evolution",
    "Chapter 7": "Human Health and Disease",
    "Chapter 8": "Microbes in Human Welfare",
    "Chapter 9": "Biotechnology: Principles and Processes",
    "Chapter 10": "Biotechnology and Its Applications",
    "Chapter 11": "Organisms and Populations",
    "Chapter 12": "Ecosystem",
    "Chapter 13": "Biodiversity and Conservation"
  },
  "Chemistry": {
    "Chapter 1": "Solutions",
    "Chapter 2": "Electrochemistry",
    "Chapter 3": "Chemical Kinetics",
    "Chapter 4": "The d- and f-Block Elements",
    "Chapter 5": "Coordination Compounds",
     "Chapter 6": "Haloalkanes and Haloarenes",
    "Chapter 7": "Alcohols, Phenols and Ethers",
    "Chapter 8": "Aldehydes, Ketones and Carboxylic Acids",
    "Chapter 9": "Amines",
    "Chapter 10": "Biomolecules"
  },
  "Physics": {
    "Chapter 1": "Electric Charges and Fields",
    "Chapter 2": "Electrostatic Potential and Capacitance",
    "Chapter 3": "Current Electricity",
    "Chapter 4": "Moving Charges and Magnetism",
    "Chapter 5": "Magnetism and Matter",
    "Chapter 6": "Electromagnetic Induction",
    "Chapter 7": "Alternating Current",
    "Chapter 8": "Electromagnetic Waves",
    "Chapter 9": "Ray Optics and Optical Instruments",
    "Chapter 10": "Wave Optics",
    "Chapter 11": "Dual Nature of Radiation and Matter",
    "Chapter 12": "Atoms",
    "Chapter 13": "Nuclei",
    "Chapter 14": "Semiconductor Electronics: Materials, Devices and Simple Circuits"
  },
  "Maths": {
    "Chapter 1": "Relations and Functions",
    "Chapter 2": "Inverse Trigonometric Functions",
    "Chapter 3": "Matrices",
    "Chapter 4": "Determinants",
    "Chapter 5": "Continuity and Differentiability",
    "Chapter 6": "Application of Derivatives",
    "Chapter 7": "Integrals",
    "Chapter 8": "Application of Integrals",
    "Chapter 9": "Differential Equations",
    "Chapter 10": "Vector Algebra",
    "Chapter 11": "Three-Dimensional Geometry",
    "Chapter 12": "Linear Programming",
    "Chapter 13": "Probability"
  }
,
    "Accountancy-Part1": {
  "Chapter 1": "Accounting for Partnership Firms- Basic Concepts",
  "Chapter 2": "Reconstitution of a Partnership Firm - Admission of a Partner",
  "Chapter 3": "Reconstitution of a Partnership Firm - Retirement/Death of a Partner",
  "Chapter 4": "Dissolution of Partnership Firm"
},
"Accountancy-Part2": {
    "Chapter 1": "Accounting for Share Capital",
    "Chapter 2": "Issue and Redemption of Debentures",
    "Chapter 3": "Financial Statements of a Company",
    "Chapter 4": "Analysis of Financial Statements",
    "Chapter 5": "Accounting Ratios",
    "Chapter 6": "Cash Flow Statement"
  },
  "Business Studies": {
    "Chapter 1": "Nature and Significance of Management",
    "Chapter 2": "Principles of Management",
    "Chapter 3": "Business Environment",
    "Chapter 4": "Planning",
    "Chapter 5": "Organising",
    "Chapter 6": "Staffing",
    "Chapter 7": "Directing",
    "Chapter 8": "Controlling",
    "Chapter 9": "Financial Management",
    "Chapter 10": "Marketing",
    "Chapter 11": "Consumer Protection"
  },
  "Economics-Part2": {
    "Chapter 1": "Introduction",
    "Chapter 2": "Theory of Consumer Behaviour",
    "Chapter 3": "Production and Costs",
    "Chapter 4": "The Theory of the Firm under Perfect Competition",
    "Chapter 5": "Market Equilibrium"
  },
  "Economics-Part1":{
    "Chapter 1": "Introduction",
    "Chapter 2": "National Income and Accounting",
    "Chapter 3": "Money and Banking",
    "Chapter 4": "Determination of Income and employment",
    "Chapter 5": "Government Budget and Economy",
    "Chapter 6": "Open Economy Macroeconomics"

  }

}

}
    
};

// --- Helper Functions ---

function showElement(element) {
    if (element) element.classList.remove('hidden');
}

function hideElement(element) {
    if (element) element.classList.add('hidden');
}

function updateSelection(type, value, displayName = null) {
    // Clear previous selection for the given type
    const optionsContainer = document.getElementById(`${type}-options`);
    if (optionsContainer) {
        optionsContainer.querySelectorAll('.option-button').forEach(button => {
            button.classList.remove('selected');
        });
    }

    // Set new selection
    state[type] = value;
    if (type === 'chapter') {
        state.chapterDisplayName = displayName;
        if (chapterSelectionDisplay) {
            chapterSelectionDisplay.textContent = displayName; // Update the display span
        }
        hideElement(chapterOptions); // Hide the chapter buttons after selection
    }

    // Mark the selected button
    if (value) {
        const selectedButton = optionsContainer ? optionsContainer.querySelector(`.option-button[data-value="${value}"]`) : null;
        if (selectedButton) {
            selectedButton.classList.add('selected');
        }
    }

    // Update submit button state
    updateSubmitButton();
}

function updateSubmitButton() {
    if (submitButton) {
        if (state.board && state.class && state.subject && state.chapter) {
            submitButton.disabled = false;
        } else {
            submitButton.disabled = true;
        }
    }
}

function displayMessage(sender, message, type = 'text', tableData = null) {
    if (!chatArea) {
        console.error("Error: chatArea element not found.");
        return;
    }

    const messageElement = document.createElement('div');
    messageElement.classList.add('message', sender);

    const bubbleElement = document.createElement('div');
    bubbleElement.classList.add('bubble', sender);

    if (message) {
        const contentElement = document.createElement('div');
        contentElement.innerHTML = (type === 'html') ? message : formatBotMessage(message);
        bubbleElement.appendChild(contentElement);
    }

    // Safely add table (if present)
    if (tableData && tableData.headers && tableData.rows) {
        const tableHtml = generateTableHtml(tableData);
        // const tableHtml = tableData;
        const wrapper = document.createElement('div');
        wrapper.innerHTML = tableHtml;
        bubbleElement.appendChild(wrapper);
    }

    messageElement.appendChild(bubbleElement);
    chatArea.appendChild(messageElement);
    chatArea.scrollTop = chatArea.scrollHeight;
}


function showProcessingMessage() {
    if (!chatArea) {
        console.error("Chat area element not found for processing message!");
        return;
    }
    processingMessageElement = document.createElement('div');
    processingMessageElement.classList.add('message', 'bot', 'processing');
    processingMessageElement.innerHTML = `
        <div class="bubble bot">
            <div class="processing-message">
                Processing
                <span class="processing-dots">
                    <span class="dot">.</span>
                    <span class="dot">.</span>
                    <span class="dot">.</span>
                </span>
            </div>
        </div>
    `;
    chatArea.appendChild(processingMessageElement);
    chatArea.scrollTop = chatArea.scrollHeight;
}

function hideProcessingMessage() {
    if (processingMessageElement && chatArea && chatArea.contains(processingMessageElement)) {
        chatArea.removeChild(processingMessageElement);
        processingMessageElement = null;
    }
}

function displayErrorMessage(message) {
    if (!chatArea) {
        console.error("Chat area element not found for error message!");
        return;
    }
    const messageElement = document.createElement('div');
    messageElement.classList.add('message', 'bot', 'error');
    const bubbleElement = document.createElement('div');
    bubbleElement.classList.add('bubble', 'bot');
    bubbleElement.innerHTML = `<p>Error: ${message}</p>`;
    messageElement.appendChild(bubbleElement);
    chatArea.appendChild(messageElement);
    chatArea.scrollTop = chatArea.scrollHeight;
}

// --- API Calls ---


async function loadUserData() {
    try {
        // First try to get user data from the server
        const userRes = await fetch('/api/user');
        const userData = await userRes.json();
        const user = userData.user || {};

        // Set user name
        if (userName) userName.textContent = user.name || 'Guest';
        
        // Set stream from user data
        state.stream = user.stream || 'NA';
        
        // Priority 1: Use class from user data if available
        // Note: Make sure your backend returns 'class' in the user object
        const userClass = user.class ? `Class ${user.class}` : null;
        
        // Priority 2: Fall back to localStorage if no class in user data
        const storedBoard = localStorage.getItem('userBoard');
        const storedClass = localStorage.getItem('userClass');
        
        // Set state values
        state.board = storedBoard || 'NCERT'; // Still fall back to NCERT for board
        state.class = userClass || storedClass || null; // Use user.class first, then localStorage, then null
        
        // Update UI displays
        if (displayBoard) displayBoard.textContent = state.board;
        if (displayClass) displayClass.textContent = state.class;

        // Update selection UI
        updateSelection('board', state.board);
        updateSelection('class', state.class);

        // Show subject selection if we have both board and class
        if (state.board && state.class) {
            showSubjectSelection(state.board, state.class);
        }

    } catch (err) {
        console.warn("Failed to load user or local storage data:", err);
        // Fallback to local storage only if API fails
        const storedBoard = localStorage.getItem('userBoard');
        const storedClass = localStorage.getItem('userClass');
        state.board = storedBoard || 'NCERT';
        state.class = storedClass || null;
        
        if (displayBoard) displayBoard.textContent = state.board;
        if (displayClass) displayClass.textContent = state.class;
        
        updateSelection('board', state.board);
        updateSelection('class', state.class);
        
        if (state.board && state.class) {
            showSubjectSelection(state.board, state.class);
        }
    }
}


async function getSubjects(board, classLevel, stream) {
    try {
        const subjectsRes = await fetch(`/api/get-subjects?board=${board}&class=${classLevel}&stream=${stream}`);
        const subjects = await subjectsRes.json();
        if (!Array.isArray(subjects)) throw new Error(subjects.error || 'Invalid subject data');
        return subjects;
    } catch (err) {
        console.error("Failed to load subjects:", err);
        displayErrorMessage("Failed to load subjects. Please try again.");
        return [];
    }
}

async function getChapters(subject, board, classLevel, type = '') {
    const queryParams = new URLSearchParams({
        subject,
        board,
        class: classLevel,
    });
    if (type) queryParams.append('type', type);

    try {
        const chaptersRes = await fetch(`/api/get-chapters?${queryParams}`);
        const chapters = await chaptersRes.json();
        if (!Array.isArray(chapters)) throw new Error(chapters.error || 'Invalid chapter data');
        return chapters; // This will return chapter IDs like "Chapter 1"
    } catch (err) {
        console.error("Failed to load chapters:", err);
        displayErrorMessage("Failed to load chapters. Please try again.");
        return [];
    }
}

async function sendMessage(question) {
    if (!userQuestionInput || !sendButton || !question.trim() || userQuestionInput.disabled) return;

    displayMessage('user', question); // Show user's question
    userQuestionInput.value = '';
    userQuestionInput.disabled = true;
    sendButton.disabled = true;

    showProcessingMessage();

    try {
        // Construct the full GCS path based on selected state
        const basePath = `gs://guru-ai-bucket/${state.board}/${state.class}/${state.subject}`;
        const chapterFile = `${state.chapter.replace(/ /g, '_').replace(/[()]/g, '')}.pdf`;
        const fullPath = state.subject.toLowerCase() === 'english' &&
                         parseInt(state.class.replace('Class ', '')) >= 8 &&
                         state.literatureType
            ? `${basePath}/${state.literatureType}/${chapterFile}`
            : `${basePath}/${chapterFile}`;

        const response = await fetch('/ask', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ path: fullPath, question: question })
        });

        const data = await response.json();
        hideProcessingMessage();
        userQuestionInput.disabled = false;
        sendButton.disabled = false;

        if (data.answer) {
            displayMessage('bot', data.answer); // Show bot response
        } else if (data.error) {
            displayErrorMessage(data.error);
        } else {
            displayErrorMessage("Received an unexpected response from the AI.");
        }
    } catch (error) {
        console.error('Error sending message:', error);
        hideProcessingMessage();
        userQuestionInput.disabled = false;
        sendButton.disabled = false;
        displayErrorMessage("Could not connect to the AI. Please try again.");
    }
}

async function submitPath() {
    if (!state.board || !state.class || !state.subject || !state.chapter) {
        displayErrorMessage("Please select Board, Class, Subject, and Chapter.");
        return;
    }

    let fullPath = `gs://guru-ai-bucket/${state.board}/${state.class}/${state.subject}`;
    
    // Ensure class is parsed correctly for comparison
    const classNum = parseInt(state.class.replace('Class ', ''));

    if (state.subject.toLowerCase() === 'english' && classNum >= 8 && classNum !== 11) {
        if (state.literatureType) {
            fullPath += `/${state.literatureType}`;
        } else {
            displayErrorMessage("Please select Literature type for English subject.");
            return;
        }
    }

    fullPath += `/${state.chapter.replace(/ /g, '_').replace(/[()]/g, '')}.pdf`;
    console.log("Submitting path:", fullPath);

    showProcessingMessage();

    try {
        const res = await fetch('/api/chat/submit-path', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ path: fullPath })
        });
        const data = await res.json();
        hideProcessingMessage();

        if (data.status === 'success') {
            if (userQuestionInput) userQuestionInput.disabled = false;
            if (sendButton) sendButton.disabled = false;
            // Changed here: Use displayMessage instead of the removed displayBotMessage
            displayMessage("bot", "PDF loaded successfully. You can now ask your questions.");
        } else {
            displayErrorMessage('Error loading material: ' + (data.message || 'Unknown error'));
        }
    } catch (err) {
        console.error('Submit error:', err);
        hideProcessingMessage();
        displayErrorMessage("Failed to load material. Please check your network and try again.");
    }
}


// --- UI Display Functions ---



async function showSubjectSelection(board, classLevel) {
    if (!board || !classLevel) return;

    // Clear previous selections for subsequent steps
    updateSelection('subject', null);
    updateSelection('chapter', null);
    state.literatureType = null;
    if (chapterSelectionDisplay) chapterSelectionDisplay.textContent = "Select Chapter";

    // Clear and hide next levels
    if (subjectOptions) subjectOptions.innerHTML = '';
    if (chapterOptions) chapterOptions.innerHTML = '';
    hideElement(chapterMessage);
    hideElement(chapterSelectContainer);
    hideElement(document.getElementById('literatureType'));

    showElement(subjectMessage);
    showElement(subjectOptions);

    const subjects = await getSubjects(board, classLevel.replace('Class ', ''), state.stream); // Remove "Class " prefix
    if (subjects.length === 0) {
        if (subjectOptions) subjectOptions.innerHTML = '<p>No subjects available for this class.</p>';
        return;
    }

    subjects.forEach(sub => {
        const button = document.createElement('button');
        button.classList.add('option-button');
        button.dataset.value = sub;
        button.textContent = sub;
        button.onclick = () => {
            updateSelection('subject', sub);
            const classNum = parseInt(state.class.replace('Class ', ''));
            if (sub.toLowerCase() === 'english' && classNum >= 8 && classNum !== 11) {
                const literatureTypeElement = document.getElementById('literatureType');
                if (literatureTypeElement) {
                    showElement(literatureTypeElement);
                    state.literatureType = null;
                    literatureTypeElement.value = "";
                    literatureTypeElement.onchange = () => {
                        state.literatureType = literatureTypeElement.value;
                        showChapterSelection(state.subject, state.board, state.class, state.literatureType);
                    };
                }
            } else {
                hideElement(document.getElementById('literatureType'));
                state.literatureType = null;
                showChapterSelection(state.subject, state.board, state.class);
            }
        };
        if (subjectOptions) subjectOptions.appendChild(button);
    });
}

// chat1.js

// ... (Keep all your existing global DOM element references and state object) ...
// ... (Keep your existing classSubjectChapterNames object as it is) ...
// ... (Keep your helper functions like showElement, hideElement, updateSelection, displayErrorMessage, etc.) ...
// ... (Keep your API calls like getSubjects, getChapters - ensure getChapters returns chapter IDs like ["Chapter 1", "Chapter 2"]) ...


async function showChapterSelection(subject, board, classLevel, literatureType = '') {
    if (!subject || !board || !classLevel) {
        console.error("Missing parameters for showChapterSelection:", { subject, board, classLevel });
        return;
    }

    // Reset chapter selection in state and UI
    updateSelection('chapter', null); // Clears chapter ID and display name
    if (chapterOptions) chapterOptions.innerHTML = ''; // Clear previous chapter buttons
    if (chapterSelectionDisplay) chapterSelectionDisplay.textContent = "Select Chapter"; // Reset display text

    // Show relevant UI elements for chapter selection
    showElement(chapterMessage);
    showElement(chapterSelectContainer);
    showElement(chapterOptions); // Ensure the container for chapter buttons is visible

    // Call the backend API to get the list of available chapter IDs for the current selection
    // The backend should return an array like ["Chapter 1", "Chapter 2", "Chapter 3"]
    const chapterIds = await getChapters(subject, board, classLevel.replace('Class ', ''), literatureType);

    // Check if any chapters were returned
    if (chapterIds.length === 0) {
        if (chapterOptions) chapterOptions.innerHTML = '<p>No chapters available for this selection.</p>';
        hideElement(chapterSelectContainer); // Hide the whole container if no chapters
        hideElement(chapterMessage);
        return;
    }

    // --- Determine the correct mapping for descriptive names ---
    // This logic relies on your classSubjectChapterNames structure being correct.
    let chapterNamesMap = null;
    try {
        if (literatureType) {
            // For English literature, go deeper: classSubjectChapterNames[board][classLevel][subject][literatureType]
            chapterNamesMap = classSubjectChapterNames[board]?.[classLevel]?.[subject]?.[literatureType];
        } else {
            // For other subjects: classSubjectChapterNames[board][classLevel][subject]
            chapterNamesMap = classSubjectChapterNames[board]?.[classLevel]?.[subject];
        }
    } catch (e) {
        console.warn("Error accessing classSubjectChapterNames map, might be missing entry:", e);
        // If the map path is invalid, chapterNamesMap will be null
    }

    let chaptersToDisplay = [];
    chapterIds.forEach(chapterId => {
        let chapterName = chapterId; // Default to the ID if no descriptive name found
        
        if (chapterNamesMap && chapterNamesMap[chapterId]) {
            chapterName = chapterNamesMap[chapterId]; // Use the descriptive name from the map
        } else {
            // This fallback will trigger if the backend returns an ID for which
            // there is no corresponding entry in your frontend's classSubjectChapterNames.
            // This suggests a potential mismatch or missing data in classSubjectChapterNames.
            console.warn(`Descriptive name not found in classSubjectChapterNames for ${board}-${classLevel}-${subject}-${literatureType || 'General'} -> ${chapterId}. Falling back to Chapter ${parseInt(chapterId.replace('Chapter ', ''))}.`);
            chapterName = `Chapter ${parseInt(chapterId.replace('Chapter ', ''))}`; // Generate generic name
        }
        chaptersToDisplay.push({ id: chapterId, name: chapterName });
    });

    // Sort chapters numerically based on their ID (e.g., "Chapter 1" before "Chapter 10")
    chaptersToDisplay.sort((a, b) => {
        const numA = parseInt(a.id.replace('Chapter ', ''));
        const numB = parseInt(b.id.replace('Chapter ', ''));
        return numA - numB;
    });

    // Render buttons for each chapter
    chaptersToDisplay.forEach(chapter => {
        const button = document.createElement('button');
        button.classList.add('option-button');
        button.dataset.value = chapter.id;      // Store the backend-expected ID (e.g., "Chapter 1")
        button.textContent = chapter.name;      // Display the user-friendly name (e.g., "Real Numbers")
        button.onclick = () => {
            // When clicked, update state with both ID and display name
            updateSelection('chapter', chapter.id, chapter.name);
        };
        if (chapterOptions) chapterOptions.appendChild(button);
    });
}

// ... (Keep the rest of your chat1.js code unchanged below this function) ...
// --- Initialization ---

async function init() {
    await loadUserData();
    

    if (sendButton) {
        sendButton.addEventListener('click', () => sendMessage(userQuestionInput.value));
    }
    if (userQuestionInput) {
        userQuestionInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                sendMessage(userQuestionInput.value);
            }
        });
    }

    if (submitButton) {
        submitButton.addEventListener('click', submitPath);
    }
    
    updateSubmitButton();
}

function formatBotMessage(text) {
    // First handle chemical equations and formulas
    text = formatChemicalContent(text);

    // Then handle tables
    const tableRegex = /(\|.+\|[\r\n]+)((?:\|.+\|[\r\n]+)+)/g;
    const tables = [];
    let tableIndex = 0;

    // Extract and store tables
    text = text.replace(tableRegex, (match, headerRow, bodyRows) => {
        const rows = [headerRow, ...bodyRows.split('\n').filter(r => r.trim())];
        const tableData = { headers: [], rows: [] };
        
        // Process header row
        const headerCells = headerRow.split('|').slice(1, -1).map(c => c.trim());
        tableData.headers = headerCells;
        
        // Process body rows (skip separator lines)
        rows.slice(1).forEach(row => {
            if (!/^[\s|:-]+$/.test(row)) { // Skip separator lines
                const cells = row.split('|').slice(1, -1).map(c => {
                    // Format bold text in cells
                    return c.trim().replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
                });
                if (cells.length === headerCells.length) {
                    tableData.rows.push(cells);
                }
            }
        });
        
        tables.push(tableData);
        return `[TABLE_PLACEHOLDER_${tableIndex++}]`;
    });

    // Format bold and italic in non-table text
    text = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
    text = text.replace(/_(.*?)_/g, '<em>$1</em>');
    text = text.replace(/\*(.*?)\*/g, '<em>$1</em>');
    text = text.replace(/\n/g, '<br>');
    text = text.replace(/\#\#\#\#(.*?)\n/g, '<u><strong>$1</strong></u>');
    text = text.replace(/\#\#\#(.*?)\n/g, '<u><strong>$1</strong></u>');

    // Handle headings
    text = text.replace(/^###### (.*)$/gm, '<h6>$1</h6>');
    text = text.replace(/^##### (.*)$/gm, '<h5>$1</h5>');
    text = text.replace(/^#### (.*)$/gm, '<h4>$1</h4>');
    text = text.replace(/^### (.*)$/gm, '<h3>$1</h3>');
    text = text.replace(/^## (.*)$/gm, '<h2>$1</h2>');
    text = text.replace(/^# (.*)$/gm, '<h1>$1</h1>');

    // Convert bullet points to lists
    text = text.replace(/(^|\n)([-*]) (.+)/g, (match, p1, p2, p3) => {
        return `${p1}<ul><li>${p3}</li></ul>`;
    });
    text = text.replace(/<\/ul>\s*<ul>/g, '');

    // Handle numbered lists
    text = text.replace(/(^|\n)(\d+)\. (.+)/g, (match, p1, p2, p3) => {
        return `${p1}<ol start="${p2}"><li>${p3}</li></ol>`;
    });
    text = text.replace(/<\/ol>\s*<ol/g, '</ol><ol');

    // Replace table placeholders with HTML
    tables.forEach((tableData, index) => {
        const tableHtml = generateTableHtml(tableData);
        // text = text.replace(`[TABLE_PLACEHOLDER_${index}]`, tableHtml);
        text = formatBotMessage(tableHtml);
    });

    return text;
}

function generateTableHtml(tableData) {
    if (!tableData.headers || tableData.headers.length === 0) return '';
    
    let html = '<div class="table-container"><table class="chat-table"><thead><tr>';
    
    // Add headers with bold formatting
    tableData.headers.forEach(header => {
        const formattedHeader = header.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
        html += `<th>${formattedHeader}</th>`;
    });
    html += '</tr></thead><tbody>';
    
    // Add rows (skip empty rows)
    tableData.rows.forEach(row => {
        // Skip rows that are all empty or separators
        if (!row.every(cell => cell.trim() === '' || cell.trim() === '--')) {
            html += '<tr>';
            row.forEach(cell => {
                html += `<td>${cell}</td>`;
            });
            html += '</tr>';
        }
    });
    
    html += '</tbody></table></div>';
    return html;
}

function formatChemicalContent(text) {
    // Format chemical equations
    text = text.replace(/(\d*)([A-Z][a-z]?\d*)([+-→=<>]+)(\d*)([A-Z][a-z]?\d*)/g, 
        (match, coef1, formula1, arrow, coef2, formula2) => {
            return `${coef1}<span class="chemical-formula">${formatSubscripts(formula1)}</span>` +
                   `<span class="reaction-arrow">${arrow}</span>` +
                   `${coef2}<span class="chemical-formula">${formatSubscripts(formula2)}</span>`;
        });

    // Format state symbols (s), (l), (g), (aq)
    text = text.replace(/\(([slgaq]{1,3})\)/g, '<sub class="state-symbol">($1)</sub>');

    // Format chemical formulas in text
    text = text.replace(/([A-Z][a-z]?\d+)/g, (match, formula) => {
        return `<span class="chemical-formula">${formatSubscripts(formula)}</span>`;
    });

    // Format reaction types
    text = text.replace(/(Combination|Decomposition|Displacement|Double Displacement|Precipitation|Redox) Reaction/g, 
        '<strong class="reaction-type">$1 Reaction</strong>');

    return text;
}

function formatSubscripts(formula) {
    // Convert numbers in chemical formulas to subscripts (H2O → H₂O)
    return formula.replace(/(\d+)/g, '<sub>$1</sub>');
}


document.addEventListener('DOMContentLoaded', init);