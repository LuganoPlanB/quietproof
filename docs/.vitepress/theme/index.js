import DefaultTheme from "vitepress/theme";
import "lugano-planb-vite-theme/theme.css";
import HomePage from "./components/HomePage.vue";
import Layout from "./Layout.vue";
import "./custom.css";

export default {
  extends: DefaultTheme,
  Layout,
  enhanceApp({ app }) {
    app.component("HomePage", HomePage);
  },
};
