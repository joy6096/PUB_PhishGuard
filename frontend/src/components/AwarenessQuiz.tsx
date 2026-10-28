
import { useEffect, useState } from 'react';
import {
  ArrowLeft,
  BookOpen,
  CheckCircle2,
  RotateCcw,
  ShieldCheck,
  Trash2,
  Trophy,
  XCircle,
} from 'lucide-react';
import {
  clearQuizHistory,
  readQuizHistory,
  saveQuizResult,
  type QuizHistoryEntry,
} from '../utils/quizHistory';
import './AwarenessQuiz.css';

type Question = {
  question: string;
  options: string[];
  answer: number;
  explanation: string;
  topic: string;
};

const QUESTIONS: Question[] = [
  {
    question: 'একটি SMS বলছে, আপনার mobile banking account বন্ধ হয়ে যাবে। Account চালু রাখতে এখনই একটি link-এ PIN দিতে হবে। কী করবেন?',
    options: [
      'Link খুলে PIN দেব',
      'SMS-এ দেওয়া নম্বরে PIN পাঠাব',
      'Link ব্যবহার না করে official app বা verified support দিয়ে যাচাই করব',
      'একই SMS বন্ধুদের পাঠাব',
    ],
    answer: 2,
    topic: 'Urgency and payment credentials',
    explanation: 'Account বন্ধের ভয় দেখিয়ে PIN বা sensitive তথ্য চাওয়া phishing-এর লক্ষণ। SMS-এর link বা নম্বর ব্যবহার না করে নিজে official app বা verified support খুঁজে নিন।',
  },
  {
    question: 'একটি email-এর display name “University IT Support”, কিন্তু sender address অচেনা domain-এর। কোন পদক্ষেপটি সবচেয়ে নিরাপদ?',
    options: [
      'Display name পরিচিত, তাই email বিশ্বাস করব',
      'Sender address এবং request official channel দিয়ে যাচাই করব',
      'Email-এ থাকা attachment সঙ্গে সঙ্গে খুলব',
      'Email-এ reply করে password চাইব',
    ],
    answer: 1,
    topic: 'Sender spoofing',
    explanation: 'Display name সহজেই নকল করা যায়। পুরো sender address, domain এবং অনুরোধটি official university channel দিয়ে যাচাই করুন।',
  },
  {
    question: 'একটি website-এর ঠিকানা `https://bank.example.com.attacker.test`। শুধু HTTPS দেখে কি website-টিকে বিশ্বাস করা যায়?',
    options: [
      'হ্যাঁ, HTTPS থাকলে website আসল',
      'হ্যাঁ, URL লম্বা হলেও সমস্যা নেই',
      'না, domain-এর আসল অংশ সতর্কভাবে যাচাই করতে হবে',
      'হ্যাঁ, browser খুলতে পারলে নিরাপদ',
    ],
    answer: 2,
    topic: 'Domain inspection',
    explanation: 'HTTPS সংযোগ encrypt করতে পারে, কিন্তু website-এর মালিক সত্যিকারের bank কি না তা প্রমাণ করে না। এখানে domain-এর শেষ registrable অংশ `attacker.test`—`bank.example.com` নয়।',
  },
  {
    question: 'কেউ ফোন করে আপনার account “verify” করার জন্য OTP চাইছে। কী করবেন?',
    options: [
      'OTP দিয়ে দেব, কারণ caller জানে আমার নাম',
      'OTP-এর অর্ধেক বলব',
      'কোনো OTP দেব না; official channel দিয়ে যোগাযোগ করব',
      'Caller-কে password-ও দিয়ে দেব',
    ],
    answer: 2,
    topic: 'OTP safety',
    explanation: 'OTP, PIN ও password কাউকে জানাবেন না—caller নিজেকে bank, mobile financial service বা support staff বললেও নয়।',
  },
  {
    question: 'অপ্রত্যাশিত email-এ `invoice.pdf.exe` নামে attachment এসেছে। কী বোঝা উচিত?',
    options: [
      'নাম PDF দিয়ে শুরু, তাই নিরাপদ',
      'Double extension সন্দেহজনক; খুলব না এবং official source দিয়ে যাচাই করব',
      'কম্পিউটারে download করলেই নিরাপদ',
      'ফাইলটি অন্য কাউকে পাঠিয়ে পরীক্ষা করব',
    ],
    answer: 1,
    topic: 'Risky attachments',
    explanation: 'Double extension দিয়ে executable file-কে document মনে করানোর চেষ্টা হতে পারে। অপ্রত্যাশিত attachment খুলবেন না; প্রতিষ্ঠানের IT/security team-কে জানাতে পারেন।',
  },
  {
    question: 'একটি social media message বলছে “আপনি পুরস্কার জিতেছেন”, কিন্তু পুরস্কার পেতে আগে fee দিতে হবে। সবচেয়ে নিরাপদ পদক্ষেপ কী?',
    options: [
      'Fee পাঠিয়ে পুরস্কার দাবি করব',
      'National ID ও banking details পাঠাব',
      'স্বাধীনভাবে official source যাচাই করব এবং আগাম টাকা দেব না',
      'Message-টি সত্যি কি না দেখতে link-এ login করব',
    ],
    answer: 2,
    topic: 'Prize scams',
    explanation: 'ভুয়া পুরস্কারের নামে advance fee বা ব্যক্তিগত তথ্য চাওয়া সাধারণ scam pattern। Message-এর link নয়, স্বাধীনভাবে পাওয়া official source ব্যবহার করুন।',
  },
  {
    question: 'কোনো message-এ sender-এর email domain-এ `paypaI.com` লেখা—শেষের অক্ষরটি ছোট হাতের L-এর বদলে বড় হাতের I হতে পারে। কী ঝুঁকি আছে?',
    options: [
      'এটি সবসময় আসল domain',
      'Look-alike বা typosquatting domain হতে পারে',
      'Capital letter থাকলে domain যাচাই হয়ে যায়',
      'শুধু logo দেখলেই যথেষ্ট',
    ],
    answer: 1,
    topic: 'Look-alike domains',
    explanation: 'আসল domain-এর মতো দেখতে অক্ষর ব্যবহার করে নকল domain বানানো হয়। Logo বা display text-এর বদলে domain spelling official source-এর সঙ্গে মিলিয়ে নিন।',
  },
  {
    question: 'একটি email-এ “আপনার account আজই বন্ধ হবে” বলা হয়েছে এবং সঙ্গে সঙ্গে login করতে চাপ দেওয়া হয়েছে। কোন signal সবচেয়ে স্পষ্ট?',
    options: [
      'Urgency বা ভয় দেখিয়ে দ্রুত সিদ্ধান্ত নিতে বাধ্য করা',
      'Email-এ greeting থাকা',
      'Email-এ তারিখ লেখা',
      'Email-এ signature থাকা',
    ],
    answer: 0,
    topic: 'Urgency and manipulation',
    explanation: 'জরুরি সময়সীমা, ভয় বা চাপ ব্যবহার করে মানুষকে যাচাই না করেই click করানো phishing-এর সাধারণ কৌশল। ধীরে যাচাই করুন।',
  },
  {
    question: 'একটি email-এ SPF/DKIM/DMARC authentication result দেখা যাচ্ছে। এগুলো কী প্রমাণ করে?',
    options: [
      'Email-এর প্রতিটি বক্তব্য সত্য',
      'Link ও attachment নিশ্চিতভাবে নিরাপদ',
      'কিছু email-authentication check-এর ফল; তবু message-এর বিষয়বস্তু যাচাই দরকার',
      'Sender-এর account কখনো compromised হতে পারে না',
    ],
    answer: 2,
    topic: 'Email authentication',
    explanation: 'Authentication checks domain/email infrastructure সম্পর্কে তথ্য দেয়; এগুলো message-এর উদ্দেশ্য বা প্রতিটি link নিরাপদ হওয়ার নিশ্চয়তা নয়। Compromised legitimate account থেকেও scam আসতে পারে।',
  },
  {
    question: 'আপনি ভুল করে একটি suspicious link-এ click করেছেন। এরপর কী করা উচিত?',
    options: [
      'Page যা বলে সব তথ্য দিয়ে দেব',
      'Password, PIN বা OTP দিলে আরও সমস্যা নেই',
      'আর কোনো তথ্য দেব না; page বন্ধ করে প্রয়োজনমতো official support ও security team-কে জানাব',
      'Link-টি আরও কয়েকবার খুলে পরীক্ষা করব',
    ],
    answer: 2,
    topic: 'Incident response',
    explanation: 'আর কোনো তথ্য দেবেন না বা file download করবেন না। Password দিয়ে থাকলে পরিষ্কার/বিশ্বস্ত device থেকে official site বা app ব্যবহার করে password পরিবর্তন করুন, MFA চালু করুন এবং সংশ্লিষ্ট প্রতিষ্ঠানে রিপোর্ট করুন।',
  },
];

function formatDate(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Unknown date';
  return date.toLocaleString();
}

export default function AwarenessQuiz() {
  const [questionIndex, setQuestionIndex] = useState(0);
  const [selected, setSelected] = useState<number | null>(null);
  const [answers, setAnswers] = useState<number[]>([]);
  const [finished, setFinished] = useState(false);
  const [history, setHistory] = useState<QuizHistoryEntry[]>([]);
  const [savedResult, setSavedResult] = useState<QuizHistoryEntry | null>(null);

  useEffect(() => {
    setHistory(readQuizHistory());
  }, []);

  const question = QUESTIONS[questionIndex];
  const correctCount = answers.reduce(
    (count, answer, index) =>
      count + (answer === QUESTIONS[index]?.answer ? 1 : 0),
    0,
  );
  const percentage = Math.round((correctCount / QUESTIONS.length) * 100);

  function chooseAnswer(optionIndex: number) {
    if (selected !== null) return;
    setSelected(optionIndex);
  }

  function nextQuestion() {
    if (selected === null) return;

    const nextAnswers = [...answers];
    nextAnswers[questionIndex] = selected;
    setAnswers(nextAnswers);
    setSelected(null);

    if (questionIndex < QUESTIONS.length - 1) {
      setQuestionIndex(questionIndex + 1);
      return;
    }

    const finalCorrect = nextAnswers.reduce(
      (count, answer, index) =>
        count + (answer === QUESTIONS[index].answer ? 1 : 0),
      0,
    );

    const entry = saveQuizResult(finalCorrect, QUESTIONS.length);
    setSavedResult(entry);
    setHistory(readQuizHistory());
    setFinished(true);
  }

  function restartQuiz() {
    setQuestionIndex(0);
    setSelected(null);
    setAnswers([]);
    setFinished(false);
    setSavedResult(null);
  }

  function deleteHistory() {
    clearQuizHistory();
    setHistory([]);
  }

  if (finished) {
    return (
      <section className="quiz-page">
        <div className="quiz-topline">
          <span className="quiz-label"><ShieldCheck size={16} /> AWARENESS QUIZ</span>
        </div>

        <div className="quiz-result-card">
          <div className="quiz-trophy"><Trophy size={34} /></div>
          <span className="quiz-eyebrow">QUIZ COMPLETED</span>
          <h2>{percentage >= 80 ? 'Great awareness!' : percentage >= 50 ? 'Good start—keep learning.' : 'Keep practising safely.'}</h2>
          <div className="quiz-final-score">
            <strong>{savedResult?.percentage ?? percentage}%</strong>
            <span>{correctCount} of {QUESTIONS.length} correct</span>
          </div>
          <p className="quiz-result-copy">
            {percentage >= 80
              ? 'You recognised most of the warning signs. Stay cautious: no single signal can prove a message is safe.'
              : 'Review the explanations below to learn how to verify suspicious messages, domains and attachments.'}
          </p>

          <div className="quiz-review-list">
            {QUESTIONS.map((item, index) => {
              const userAnswer = answers[index];
              const isCorrect = userAnswer === item.answer;
              return (
                <article className="quiz-review-item" key={item.question}>
                  <div className="quiz-review-title">
                    {isCorrect ? <CheckCircle2 size={18} /> : <XCircle size={18} />}
                    <b>{index + 1}. {item.question}</b>
                  </div>
                  <p className="quiz-your-answer">
                    Your answer: {item.options[userAnswer] ?? 'Not answered'}
                  </p>
                  {!isCorrect && (
                    <p className="quiz-correct-answer">
                      Correct answer: {item.options[item.answer]}
                    </p>
                  )}
                  <p className="quiz-explanation">{item.explanation}</p>
                  <span className="quiz-topic">{item.topic}</span>
                </article>
              );
            })}
          </div>

          <div className="quiz-actions">
            <button className="quiz-primary" onClick={restartQuiz} type="button">
              <RotateCcw size={17} /> Try again
            </button>
          </div>
        </div>

        <HistoryPanel history={history} onClear={deleteHistory} />
      </section>
    );
  }

  return (
    <section className="quiz-page">
      <div className="quiz-topline">
        <span className="quiz-label"><ShieldCheck size={16} /> AWARENESS QUIZ</span>
      </div>

      <div className="quiz-intro">
        <div className="quiz-intro-icon"><BookOpen size={25} /></div>
        <span className="quiz-eyebrow">LEARN TO SPOT THE SIGNS</span>
        <h2>Think before you click.</h2>
      </div>

      <div className="quiz-card">
        <div className="quiz-progress-meta">
          <span>Question {questionIndex + 1} of {QUESTIONS.length}</span>
          <span>{Math.round(((questionIndex + 1) / QUESTIONS.length) * 100)}% progress</span>
        </div>
        <div className="quiz-progress-track">
          <div style={{ width: `${((questionIndex + 1) / QUESTIONS.length) * 100}%` }} />
        </div>

        <span className="quiz-topic">{question.topic}</span>
        <h3>{question.question}</h3>

        <div className="quiz-options">
          {question.options.map((option, index) => {
            const answered = selected !== null;
            const isCorrect = index === question.answer;
            const isSelected = index === selected;
            let className = 'quiz-option';
            if (answered && isCorrect) className += ' correct';
            else if (answered && isSelected) className += ' incorrect';

            return (
              <button
                className={className}
                key={option}
                onClick={() => chooseAnswer(index)}
                type="button"
                disabled={answered}
              >
                <span className="quiz-option-letter">{String.fromCharCode(65 + index)}</span>
                <span>{option}</span>
                {answered && isCorrect && <CheckCircle2 size={18} />}
                {answered && isSelected && !isCorrect && <XCircle size={18} />}
              </button>
            );
          })}
        </div>

        {selected !== null && (
          <div className={`quiz-feedback ${selected === question.answer ? 'feedback-correct' : 'feedback-incorrect'}`}>
            <b>{selected === question.answer ? 'Correct answer!' : 'Not quite.'}</b>
            <p>{question.explanation}</p>
          </div>
        )}

        <div className="quiz-footer">
          <span>{answers.filter((answer, index) => answer === QUESTIONS[index]?.answer).length} correct so far</span>
          <button
            className="quiz-primary"
            disabled={selected === null}
            onClick={nextQuestion}
            type="button"
          >
            {questionIndex === QUESTIONS.length - 1 ? 'See my result' : 'Next question'}
            <ArrowLeft className="quiz-arrow-next" size={17} />
          </button>
        </div>
      </div>

      <HistoryPanel history={history} onClear={deleteHistory} />
    </section>
  );
}

function HistoryPanel({
  history,
  onClear,
}: {
  history: QuizHistoryEntry[];
  onClear: () => void;
}) {
  return (
    <section className="quiz-history">
      <div className="quiz-history-heading">
        <div>
          <span className="quiz-eyebrow">YOUR PROGRESS</span>
          <h3>Score History</h3>
        </div>
        {history.length > 0 && (
          <button className="quiz-clear-history" onClick={onClear} type="button">
            <Trash2 size={15} /> Clear history
          </button>
        )}
      </div>

      {history.length === 0 ? (
        <p className="quiz-history-empty">Your completed quiz scores will appear here on this browser.</p>
      ) : (
        <div className="quiz-history-list">
          {history.map((item) => (
            <article className="quiz-history-row" key={item.id}>
              <div className="quiz-history-icon"><Trophy size={17} /></div>
              <div className="quiz-history-details">
                <b>{item.percentage}% · {item.correctAnswers}/{item.total} correct</b>
                <small>{formatDate(item.completedAt)}</small>
              </div>
              <span className="quiz-history-score">{item.score}/{item.total}</span>
            </article>
          ))}
        </div>
      )}
      <p className="quiz-storage-note">Stored locally in this browser only. Clearing browser site data may erase this history.</p>
    </section>
  );
}
