import { Nav } from "./components/Nav";
import { Hero } from "./components/Hero";
import { TrustStrip } from "./components/TrustStrip";
import { Features } from "./components/Features";
import { Algorithm } from "./components/Algorithm";
import { Performance } from "./components/Performance";
import { Cli } from "./components/Cli";
import { UseCases } from "./components/UseCases";
import { Cta } from "./components/Cta";
import { Footer } from "./components/Footer";

export default function App() {
  return (
    <div className="relative min-h-screen overflow-x-hidden">
      <Nav />
      <main className="relative">
        <Hero />
        <TrustStrip />
        <Features />
        <Algorithm />
        <Performance />
        <Cli />
        <UseCases />
        <Cta />
      </main>
      <Footer />
    </div>
  );
}