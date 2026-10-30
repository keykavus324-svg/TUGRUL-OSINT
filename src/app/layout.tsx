import type {Metadata, Viewport} from 'next';
import ErrorBoundary from '@/components/ErrorBoundary';
import './globals.css';
export const metadata: Metadata = {
  title: 'TUĞRUL OSİNT — Açık Kaynak İstihbarat',
  description: 'Osiris kaynak kodu üzerine geliştirilen Türkiye odaklı açık kaynak araştırma platformu.',
  applicationName: 'TUĞRUL OSİNT',
  icons: {icon:'/tugrul-mark.svg',apple:'/tugrul-mark.svg'},
  robots: {index:false,follow:false},
};
export const viewport: Viewport = {themeColor:'#D4AF37',width:'device-width',initialScale:1,colorScheme:'dark'};
export default function RootLayout({children}:Readonly<{children:React.ReactNode}>){return <html lang="tr"><body className="antialiased"><ErrorBoundary name="TUĞRUL Core">{children}</ErrorBoundary></body></html>}
