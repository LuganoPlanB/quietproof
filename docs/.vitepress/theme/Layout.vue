<script setup>
import DefaultTheme from "vitepress/theme";
import { useData } from "vitepress";
import { watch } from "vue";

const { isDark } = useData();

watch(
  isDark,
  (dark) => {
    if (typeof document !== "undefined") {
      document.documentElement.dataset.theme = dark ? "dark" : "light";
    }
  },
  { immediate: true },
);
</script>

<template>
  <DefaultTheme.Layout />
</template>
