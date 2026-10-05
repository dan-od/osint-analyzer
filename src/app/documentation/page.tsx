import { permanentRedirect } from 'next/navigation';

// Old address of the docs
export default function DocumentationPage() {
  permanentRedirect('/docs');
}
