import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createStore } from './store';
import './style.css';

createRoot(document.getElementById('root')!).render(<App store={createStore()} />);
